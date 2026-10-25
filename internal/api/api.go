// Package api serves the JSON API, the SSE live stream and the embedded UI.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n0cl0ud/paindash/internal/auth"
	"github.com/n0cl0ud/paindash/internal/live"
	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
	"github.com/n0cl0ud/paindash/internal/view"
)

type Server struct {
	Store  *store.Store
	Hub    *live.Hub
	Envs   []string // switcher order; envs seen in the inventory are appended
	Source string
	Demo   bool
	Auth   func(http.Handler) http.Handler // nil: no authentication (local dev)
	UI     fs.FS                           // built web/dist, nil if absent
	Log    *slog.Logger

	// Owners are the GitHub owners whose images we build, GitOpsRepo the repo
	// of the cluster manifests ("owner/name"): where the fix prompt sends fixes.
	Owners     []string
	GitOpsRepo string
	// Promotion is the order fixes travel through the envs (e.g. dev, test,
	// prod): only an earlier env's image can be promoted to a later one.
	Promotion []string
	// AuthDisabled: anyone reaching the port is served, the UI says so.
	AuthDisabled bool
	// SignOut: Auth keeps its own session cookie (oidc, local), ended by
	// POST /auth/logout.
	SignOut bool

	// HistoryEvery coalesces history points (default 5 min).
	HistoryEvery time.Duration
	// HistoryBackfill, when set, invents the past of an env without history
	// (demo only), ending at its first real point.
	HistoryBackfill func(env string, first model.HistoryPoint) []model.HistoryPoint

	mu         sync.Mutex
	cached     *model.Dataset
	cachedAt   int64     // store version of the cached dataset
	cachedTime time.Time // when it was loaded

	closeOnce sync.Once
	closing   chan struct{}

	viewsMu  sync.Mutex
	viewsFor *model.Dataset // dataset the cached views were computed from
	views    map[viewKey]*envView
}

// A page loads the summary, two findings lists and the workloads of the same
// env and scope, and prefetches the other envs: compute each (dataset, env,
// scope) once and serve every request from it.
type viewKey struct{ env, ns, wl, exp string }

type envView struct {
	once      sync.Once
	findings  []model.Finding
	summary   model.Summary
	workloads []model.Workload
}

// envView returns the views of env under the request's scope.
func (s *Server) envView(ds *model.Dataset, env string, q url.Values) *envView {
	key := viewKey{env, q.Get("ns"), q.Get("wl"), q.Get("exp")}
	s.viewsMu.Lock()
	if s.viewsFor != ds {
		s.viewsFor, s.views = ds, map[viewKey]*envView{}
	}
	v, ok := s.views[key]
	if !ok {
		v = &envView{}
		s.views[key] = v
	}
	s.viewsMu.Unlock()
	v.once.Do(func() {
		sds := view.Scope(ds, csv(key.ns), csv(key.wl), csv(key.exp))
		v.findings = view.Findings(sds, env)
		view.KeepPromotions(v.findings, env, s.Promotion)
		v.summary = view.Summary(sds, env, v.findings)
		v.workloads = view.WorkloadsFrom(sds, env, v.findings)
	})
	return v
}

func (s *Server) closingCh() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing == nil {
		s.closing = make(chan struct{})
	}
	return s.closing
}

// CloseStreams ends the long-lived /api/stream responses so that a graceful
// shutdown does not wait for them; browsers reconnect to the new pod.
func (s *Server) CloseStreams() {
	s.closeOnce.Do(func() { close(s.closingCh()) })
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/meta", s.meta)
	api.HandleFunc("GET /api/summary", s.summary)
	api.HandleFunc("GET /api/findings", s.findings)
	api.HandleFunc("GET /api/workloads", s.workloads)
	api.HandleFunc("GET /api/workloads/{cluster}/{namespace}/{kind}/{name}", s.workload)
	api.HandleFunc("GET /api/images", s.images)
	api.HandleFunc("GET /api/origins", s.origins)
	api.HandleFunc("GET /api/exceptions", s.exceptions)
	api.HandleFunc("GET /api/exceptions/openvex", s.openVEX)
	api.HandleFunc("POST /api/exceptions", s.addException)
	api.HandleFunc("POST /api/exceptions/{id}/revoke", s.revokeException)
	api.HandleFunc("GET /api/events", s.events)
	api.HandleFunc("GET /api/history", s.history)
	api.HandleFunc("GET /api/stream", s.stream)
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})

	root := http.NewServeMux()
	root.Handle("/api/", api)
	root.Handle("/", s.ui())
	var h http.Handler = root
	if s.Auth != nil {
		h = s.Auth(h)
	}
	return securityHeaders(h)
}

// dataset returns the read model, reloaded only after a store write.
func (s *Server) dataset(ctx context.Context) (*model.Dataset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.Store.Version()
	// During a scan the store changes every second or so: reload at most every
	// 2 s, so that a burst of requests (an SSE invalidation reaching every
	// browser) costs one load.
	if s.cached != nil && (s.cachedAt == v || time.Since(s.cachedTime) < 2*time.Second) {
		return s.cached, nil
	}
	ds, err := s.Store.Dataset(ctx)
	if err != nil {
		return nil, err
	}
	s.cached, s.cachedAt, s.cachedTime = ds, v, time.Now()
	return ds, nil
}

func (s *Server) envInfos(ds *model.Dataset) []model.EnvInfo {
	clusters := map[string]map[string]bool{}
	for _, e := range s.Envs {
		clusters[e] = map[string]bool{}
	}
	for _, c := range ds.Containers {
		if clusters[c.Env] == nil {
			clusters[c.Env] = map[string]bool{}
		}
		clusters[c.Env][c.Cluster] = true
	}
	names := slices.Clone(s.Envs)
	var extra []string
	for e := range clusters {
		if !slices.Contains(names, e) {
			extra = append(extra, e)
		}
	}
	sort.Strings(extra)
	names = append(names, extra...)

	out := make([]model.EnvInfo, 0, len(names))
	for _, e := range names {
		cl := make([]string, 0, len(clusters[e]))
		for c := range clusters[e] {
			cl = append(cl, c)
		}
		sort.Strings(cl)
		out = append(out, model.EnvInfo{Name: e, Clusters: cl})
	}
	return out
}

func (s *Server) env(r *http.Request) string {
	if e := r.URL.Query().Get("env"); e != "" {
		return e
	}
	if len(s.Envs) > 0 {
		return s.Envs[0]
	}
	return "prod"
}

// scoped applies the optional ?ns=a,b&wl=ns/name,... scope of a request.
func scoped(r *http.Request, ds *model.Dataset) *model.Dataset {
	q := r.URL.Query()
	return view.Scope(ds, csv(q.Get("ns")), csv(q.Get("wl")), csv(q.Get("exp")))
}

func csv(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	var m model.Meta
	m.Envs = s.envInfos(ds)
	m.User = auth.UserFrom(r.Context())
	m.VulnDB.BuiltAt = stateTime(ds, store.StateVulnDBBuilt)
	m.VulnDB.CheckedAt = stateTime(ds, store.StateVulnDBChecked)
	m.Inventory.Source = s.Source
	// Read live: an inventory sync that changed nothing does not reload ds.
	if t, err := s.Store.StateTime(r.Context(), store.StateInventorySync); err == nil && !t.IsZero() {
		m.Inventory.LastSyncAt = &t
	}
	m.ExposureAvailable = ds.State[store.StateExposure] == "1"
	m.Demo = s.Demo
	m.GitOpsRepo = s.GitOpsRepo
	m.Promotion = nonNilStrings(s.Promotion)
	m.AuthDisabled = s.AuthDisabled
	m.SignOut = s.SignOut
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.envView(ds, s.env(r), r.URL.Query()).summary)
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	include := csv(q.Get("include"))
	flt := view.Filter{
		KEV: q.Get("kev") == "1", Fixable: q.Get("fixable") == "1", Query: q.Get("q"),
		IncludeSuspect: slices.Contains(include, "suspect"), IncludeExcepted: slices.Contains(include, "excepted"),
	}
	for _, sev := range strings.Split(q.Get("severity"), ",") {
		if sev = strings.TrimSpace(sev); sev != "" {
			flt.Severities = append(flt.Severities, model.ParseSeverity(sev))
		}
	}
	limit := intParam(q.Get("limit"), 500, 5000)

	items := []model.Finding{}
	total := 0
	for _, f := range s.envView(ds, s.env(r), r.URL.Query()).findings {
		if !flt.Match(f) {
			continue
		}
		total++
		if len(items) < limit {
			items = append(items, f)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) workloads(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": s.envView(ds, s.env(r), r.URL.Query()).workloads})
}

func (s *Server) workload(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	ref := model.WorkloadRef{
		Cluster: r.PathValue("cluster"), Namespace: r.PathValue("namespace"),
		Kind: r.PathValue("kind"), Name: r.PathValue("name"),
	}
	env := ""
	for _, c := range ds.Containers {
		if c.WorkloadRef == ref {
			env = c.Env
			break
		}
	}
	if env == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "workload not running"})
		return
	}
	var detail model.WorkloadDetail
	// Scoped to the workload: package versions and locations are its own, not
	// merged with the other workloads of the env.
	ev := s.envView(ds, env, url.Values{"wl": {ref.Namespace + "/" + ref.Name}})
	for _, wl := range ev.workloads {
		if wl.WorkloadRef == ref {
			detail.Workload = wl
		}
	}
	detail.Workload.Containers = slices.Clone(detail.Workload.Containers) // the cached view is shared
	for i, wc := range detail.Workload.Containers {
		for _, c := range ds.Containers {
			if c.WorkloadRef == ref && c.Container == wc.Name && c.Digest == wc.Digest {
				o := view.Origin(c.Image, c.Source, c.Revision, s.Owners)
				detail.Workload.Containers[i].Origin = &o
				break
			}
		}
	}
	detail.Findings = []model.Finding{}
	for _, f := range ev.findings {
		if (view.Filter{}).Match(f) && slices.ContainsFunc(f.Workloads, func(a model.AffectedContainer) bool { return a.WorkloadRef == ref }) {
			detail.Findings = append(detail.Findings, f)
		}
	}
	writeJSON(w, http.StatusOK, detail)
}

// origins tells where every running image comes from, by digest: the fix
// prompt of a vulnerability routes each affected image with it.
func (s *Server) origins(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	out := map[string]model.ImageOrigin{}
	for _, c := range ds.Containers {
		if _, ok := out[c.Digest]; !ok {
			out[c.Digest] = view.Origin(c.Image, c.Source, c.Revision, s.Owners)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// images lists the failed (default) or pending images of an env, so that a
// failure can be traced to its image, cause and workloads.
func (s *Server) images(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	statuses := []string{"failed"}
	if r.URL.Query().Get("status") == "pending" {
		statuses = []string{"pending", "scanning"}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": view.Images(scoped(r, ds), s.env(r), statuses)})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	evs, err := s.Store.Events(r.Context(), s.env(r), intParam(r.URL.Query().Get("limit"), 50, 500))
	if err != nil {
		s.fail(w, err)
		return
	}
	if evs == nil {
		evs = []model.LiveEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": evs})
}

// stream pushes live events and invalidations as Server-Sent Events. SSE goes
// through reverse proxies (Traefik, Pomerium...) as a plain long-lived HTTP
// response; the ping keeps idle timeouts at bay.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, "retry: 3000\n\n"); err != nil || rc.Flush() != nil {
		return
	}

	msgs, unsubscribe := s.Hub.Subscribe(s.env(r))
	defer unsubscribe()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	closing := s.closingCh()
	for {
		var err error
		select {
		case <-r.Context().Done():
			return
		case <-closing:
			return
		case m := <-msgs:
			if m.Event != nil {
				err = writeSSE(w, "live", m.Event)
			} else {
				err = writeSSE(w, "invalidate", map[string]any{"scopes": m.Invalidate})
			}
		case <-ping.C:
			_, err = fmt.Fprint(w, ": ping\n\n")
		}
		if err != nil || rc.Flush() != nil {
			return
		}
	}
}

func writeSSE(w http.ResponseWriter, event string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	return err
}

// ui serves the built React app, falling back to index.html for client routes.
func (s *Server) ui() http.Handler {
	if s.UI == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "UI not built into this binary: run `make web`, then rebuild.", http.StatusNotFound)
		})
	}
	files := http.FileServerFS(s.UI)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" {
			if _, err := fs.Stat(s.UI, p); err != nil {
				r = r.Clone(r.Context())
				r.URL.Path, p = "/", ""
			}
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) load(w http.ResponseWriter, r *http.Request) (*model.Dataset, bool) {
	ds, err := s.dataset(r.Context())
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return ds, true
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	if errors.Is(err, context.Canceled) {
		return // the browser went away (navigation, closed tab): nothing to answer
	}
	s.Log.Error("api", "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func intParam(s string, def, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return min(n, max)
}

func stateTime(ds *model.Dataset, key string) *time.Time {
	t, err := time.Parse(time.RFC3339, ds.State[key])
	if err != nil {
		return nil
	}
	return &t
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
