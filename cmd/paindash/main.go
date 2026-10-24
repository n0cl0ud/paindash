// Command paindash serves the CVE dashboard and runs its pipeline.
//
//	paindash            run the server (configuration from PAINDASH_* env vars)
//	paindash snapshot   print the running containers seen through Prometheus
//	paindash scan REF   scan one image (repo@sha256:...) and print its findings
package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/n0cl0ud/paindash/internal/api"
	"github.com/n0cl0ud/paindash/internal/auth"
	"github.com/n0cl0ud/paindash/internal/demo"
	"github.com/n0cl0ud/paindash/internal/enrich"
	"github.com/n0cl0ud/paindash/internal/inventory"
	"github.com/n0cl0ud/paindash/internal/live"
	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/pipeline"
	"github.com/n0cl0ud/paindash/internal/scan"
	"github.com/n0cl0ud/paindash/internal/store"
	"github.com/n0cl0ud/paindash/web"
)

func main() {
	level := slog.LevelInfo
	if env("PAINDASH_LOG_LEVEL", "") == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "snapshot":
		err = snapshot(ctx)
	case len(os.Args) > 2 && os.Args[1] == "scan":
		err = scanOne(ctx, os.Args[2])
	default:
		err = run(ctx, log)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, log *slog.Logger) error {
	demoMode := boolEnv("PAINDASH_DEMO")
	envs := strings.Split(env("PAINDASH_ENVS", "prod,test,dev"), ",")

	// Either a URL, or the standard PGHOST/PGUSER/PGPASSWORD/... variables.
	dbURL := os.Getenv("PAINDASH_DATABASE_URL")
	if dbURL == "" && os.Getenv("PGHOST") == "" {
		return errors.New("set PAINDASH_DATABASE_URL or the PG* variables (PGHOST, PGUSER, PGPASSWORD, PGDATABASE)")
	}
	st, err := store.Open(ctx, dbURL, int32(intEnv("PAINDASH_DB_MAX_CONNS", 4)))
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer st.Close()

	hub := live.NewHub()
	emitter := &pipeline.Emitter{Store: st, Hub: hub, Log: log}

	var source inventory.Source
	var scanner scan.Scanner
	syncEvery := duration("PAINDASH_SYNC_INTERVAL", 30*time.Second)
	rematchEvery := duration("PAINDASH_REMATCH_INTERVAL", time.Hour)
	if demoMode {
		log.Warn("DEMO mode: simulated clusters and scanner")
		source = demo.NewSource(duration("PAINDASH_DEMO_CHANGE_EVERY", 15*time.Second))
		scanner = demo.NewScanner(duration("PAINDASH_DEMO_DB_EVERY", 2*time.Minute))
		syncEvery = duration("PAINDASH_SYNC_INTERVAL", 3*time.Second)
		rematchEvery = duration("PAINDASH_REMATCH_INTERVAL", 20*time.Second)
	} else {
		if source, err = prometheusSource(envs); err != nil {
			return err
		}
		scanner = &scan.CLI{Syft: os.Getenv("PAINDASH_SYFT"), Grype: os.Getenv("PAINDASH_GRYPE")}
		if u := os.Getenv("PAINDASH_GRYPE_DB_URL"); u != "" {
			os.Setenv("GRYPE_DB_UPDATE_URL", u) // a mirror, for air-gapped clusters; inherited by grype
		}
		if pull, ecr := os.Getenv("PAINDASH_PULL_SECRET"), list(os.Getenv("PAINDASH_ECR_REGISTRIES")); pull != "" || len(ecr) > 0 {
			dir, err := scan.PrepareDockerConfig(pull, ecr, filepath.Join(os.TempDir(), "docker"))
			if err != nil {
				return fmt.Errorf("registry auth: %w", err)
			}
			os.Setenv("DOCKER_CONFIG", dir) // inherited by syft
		}
	}

	var enricher *pipeline.Enricher
	if !demoMode && env("PAINDASH_ENRICH", "on") != "off" {
		enricher = &pipeline.Enricher{
			Client: &enrich.Client{}, Store: st, Hub: hub, Emit: emitter, Log: log,
			KEVEvery: duration("PAINDASH_KEV_INTERVAL", time.Hour), EPSSEvery: 24 * time.Hour,
		}
	}
	worker := &pipeline.Worker{
		Scanner: scanner, Store: st, Hub: hub, Emit: emitter, Enricher: enricher, Log: log,
		Concurrency: intEnv("PAINDASH_SCAN_CONCURRENCY", 2), RematchEvery: rematchEvery,
		PriorityEnv: envs[0], MaxAttempts: 3,
		ProgressEvery: duration("PAINDASH_PROGRESS_INTERVAL", time.Minute),
	}
	syncer := &pipeline.Syncer{
		Source: source, Store: st, Hub: hub, Emit: emitter, Log: log,
		Interval: syncEvery, Grace: 15 * time.Minute, OnNewImages: worker.Wake,
		Retention: duration("PAINDASH_RETENTION", 30*24*time.Hour),
	}

	srv := &api.Server{Store: st, Hub: hub, Envs: envs, Source: source.Name(), Demo: demoMode, Log: log,
		Owners:     list(os.Getenv("PAINDASH_GITHUB_OWNERS")),
		GitOpsRepo: os.Getenv("PAINDASH_GITOPS_REPO"),
		Promotion:  list(env("PAINDASH_PROMOTION", "dev,test,prod")),
	}
	if demoMode {
		// The simulated images of the fictitious "acme" org are its own.
		if len(srv.Owners) == 0 {
			srv.Owners, srv.GitOpsRepo = []string{"acme"}, cmp.Or(srv.GitOpsRepo, "acme/gitops")
		}
		srv.HistoryEvery = 20 * time.Second
		srv.HistoryBackfill = func(env string, first model.HistoryPoint) []model.HistoryPoint {
			return demo.History(env, first, 75)
		}
	}
	if ui, err := fs.Sub(web.Dist, "dist"); err == nil {
		if _, err := fs.Stat(ui, "index.html"); err == nil {
			srv.UI = ui
		}
	}
	switch mode := env("PAINDASH_AUTH", "pomerium"); mode {
	case "pomerium":
		jwks, aud := os.Getenv("PAINDASH_POMERIUM_JWKS_URL"), os.Getenv("PAINDASH_POMERIUM_AUDIENCE")
		if jwks == "" || aud == "" {
			return errors.New("PAINDASH_POMERIUM_JWKS_URL and PAINDASH_POMERIUM_AUDIENCE are required (or PAINDASH_AUTH=disabled for local dev)")
		}
		p := auth.NewPomerium(ctx, jwks, aud, os.Getenv("PAINDASH_POMERIUM_ISSUER"), list(os.Getenv("PAINDASH_ALLOWED_GROUPS")), log)
		srv.Auth = p.Middleware
	case "disabled":
		log.Warn("authentication DISABLED: anyone reaching the port can read everything and record exceptions (as \"anonymous\"); only for local use or behind an authenticating proxy")
		srv.AuthDisabled = true
	default:
		return fmt.Errorf("PAINDASH_AUTH: unknown mode %q", mode)
	}

	go hub.Run(ctx)
	go syncer.Run(ctx)
	go worker.Run(ctx)
	if enricher != nil {
		go enricher.Run(ctx)
	}

	// Public port (behind the authenticating proxy). No write timeout: /api/stream is long-lived.
	public := &http.Server{Addr: env("PAINDASH_LISTEN", ":8080"), Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	public.RegisterOnShutdown(srv.CloseStreams)
	// Internal port: probes and Prometheus scraping, never routed by the proxy.
	internal := http.NewServeMux()
	internal.Handle("GET /metrics", srv.MetricsHandler(ctx))
	internal.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	internal.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		// Busy scans can hold every pooled connection for a moment: give the
		// ping time to get one instead of flapping the pod out of the Service.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := st.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	private := &http.Server{Addr: env("PAINDASH_INTERNAL_LISTEN", ":9090"), Handler: internal, ReadHeaderTimeout: 10 * time.Second}

	errc := make(chan error, 2)
	for _, s := range []*http.Server{public, private} {
		go func() {
			log.Info("listening", "addr", s.Addr)
			if err := s.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = private.Shutdown(shutdown)
	return public.Shutdown(shutdown)
}

func prometheusSource(envs []string) (*inventory.Prometheus, error) {
	u := os.Getenv("PAINDASH_PROMETHEUS_URL")
	if u == "" {
		return nil, errors.New("set PAINDASH_PROMETHEUS_URL: a Prometheus-compatible API with the kube-state-metrics series (or PAINDASH_DEMO=1)")
	}
	classes := map[string]string{}
	for _, kv := range list(os.Getenv("PAINDASH_INGRESS_CLASSES")) {
		class, lvl, _ := strings.Cut(kv, "=")
		if lvl != model.ExposureInternet && lvl != model.ExposureInternal {
			return nil, fmt.Errorf("PAINDASH_INGRESS_CLASSES: %q: want class=internet or class=internal", kv)
		}
		classes[class] = lvl
	}
	return &inventory.Prometheus{
		URL:               u,
		Envs:              envs,
		EnvLabel:          os.Getenv("PAINDASH_ENV_LABEL"),
		ClusterLabel:      os.Getenv("PAINDASH_CLUSTER_LABEL"),
		DefaultEnv:        os.Getenv("PAINDASH_DEFAULT_ENV"),
		DefaultCluster:    os.Getenv("PAINDASH_DEFAULT_CLUSTER"),
		PublicEntrypoints: list(os.Getenv("PAINDASH_PUBLIC_ENTRYPOINTS")),
		IngressClasses:    classes,
		Client:            &http.Client{Timeout: time.Minute},
		Log:               slog.Default(),
	}, nil
}

// snapshot prints the inventory as seen through Prometheus, to validate the
// source without a database.
func snapshot(ctx context.Context) error {
	src, err := prometheusSource(strings.Split(env("PAINDASH_ENVS", "prod,test,dev"), ","))
	if err != nil {
		return err
	}
	cs, err := src.Snapshot(ctx)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ENV\tCLUSTER\tNAMESPACE\tKIND\tNAME\tCONTAINER\tIMAGE\tDIGEST\tEXPOSURE")
	for _, c := range cs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%.19s\t%s\n", c.Env, c.Cluster, c.Namespace, c.Kind, c.Name, c.Container, c.Image, c.Digest, c.Exposure)
	}
	return tw.Flush()
}

// scanOne runs the real scanner pipeline (syft, grype, parsing) on one image
// reference and prints its findings, to debug registry access or a result.
func scanOne(ctx context.Context, ref string) error {
	s := &scan.CLI{Syft: os.Getenv("PAINDASH_SYFT"), Grype: os.Getenv("PAINDASH_GRYPE")}
	built, err := s.UpdateDB(ctx)
	if err != nil {
		return err
	}
	sbom, err := s.SBOM(ctx, ref)
	if err != nil {
		return err
	}
	res, err := s.Match(ctx, sbom)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d matches (DB built %s, SBOM %d KB)\n", ref, len(res.Matches), built.Format(time.RFC3339), len(sbom)/1024)
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "VULN\tSEVERITY\tCVSS\tPACKAGE\tVERSION\tFIXED IN")
	for _, m := range res.Matches {
		cvss := "-"
		if m.Vuln.CVSS != nil {
			cvss = fmt.Sprintf("%.1f", *m.Vuln.CVSS)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", m.Vuln.ID, m.Vuln.Severity, cvss, m.Pkg.Name, m.Pkg.Version, strings.Join(m.FixedIn, ","))
	}
	return tw.Flush()
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func boolEnv(key string) bool {
	v, _ := strconv.ParseBool(os.Getenv(key))
	return v
}

func intEnv(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}

func duration(key string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
