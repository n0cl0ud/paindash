package api

import (
	"cmp"
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
)

// Metrics feed an existing Prometheus stack. They are computed in the
// background (at scrape time they can exceed a 10 s scrape timeout on a large
// inventory): a scrape only reads the last snapshot.
// envLabel is not "env": Thanos and federation overwrite series labels with
// their external labels, env included.
const envLabel = "environment"

var (
	descVulns = prometheus.NewDesc("paindash_vulnerabilities",
		"Distinct (vulnerability, package) pairs affecting running workloads.", []string{envLabel, "severity"}, nil)
	descKEV = prometheus.NewDesc("paindash_kev_vulnerabilities",
		"Distinct vulnerabilities listed in CISA KEV affecting running workloads.", []string{envLabel}, nil)
	descCritFix = prometheus.NewDesc("paindash_critical_fixable_vulnerabilities",
		"Distinct critical vulnerabilities with a fix available.", []string{envLabel}, nil)
	descImages = prometheus.NewDesc("paindash_images",
		"Running images by scan status.", []string{envLabel, "status"}, nil)
	descWorkload = prometheus.NewDesc("paindash_workload_vulnerabilities",
		"Distinct critical/high vulnerabilities per workload.", []string{envLabel, "cluster", "namespace", "kind", "workload", "severity"}, nil)
	descWorkloadKEV = prometheus.NewDesc("paindash_workload_kev_vulnerabilities",
		"Distinct KEV vulnerabilities per workload.", []string{envLabel, "cluster", "namespace", "kind", "workload"}, nil)
	descDBBuilt = prometheus.NewDesc("paindash_vulndb_built_timestamp_seconds",
		"Build time of the vulnerability database in use.", nil, nil)
	descSync = prometheus.NewDesc("paindash_inventory_last_sync_timestamp_seconds",
		"Last successful inventory sync.", nil, nil)
	descClients = prometheus.NewDesc("paindash_stream_clients",
		"Browsers connected to the live stream.", nil, nil)
	descComputed = prometheus.NewDesc("paindash_metrics_computed_timestamp_seconds",
		"When the vulnerability metrics above were last computed.", nil, nil)
)

type metricsSnapshot struct {
	metrics []prometheus.Metric
	at      time.Time
}

type collector struct {
	s    *Server
	hist *historian
	mu   sync.Mutex
	last metricsSnapshot
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descVulns, descKEV, descCritFix, descImages, descWorkload, descWorkloadKEV, descDBBuilt, descSync, descClients, descComputed} {
		ch <- d
	}
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(descClients, prometheus.GaugeValue, float64(c.s.Hub.Clients()))
	c.mu.Lock()
	snap := c.last
	c.mu.Unlock()
	if snap.at.IsZero() {
		return
	}
	ch <- prometheus.MustNewConstMetric(descComputed, prometheus.GaugeValue, float64(snap.at.Unix()))
	for _, m := range snap.metrics {
		ch <- m
	}
}

// refresh computes a new snapshot: findings once per env, reused for the
// summary and the workloads.
func (c *collector) refresh(ctx context.Context) error {
	ds, err := c.s.dataset(ctx)
	if err != nil {
		return err
	}
	var ms []prometheus.Metric
	add := func(d *prometheus.Desc, v float64, labels ...string) {
		ms = append(ms, prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...))
	}
	for _, key := range []struct {
		desc *prometheus.Desc
		key  string
	}{{descDBBuilt, store.StateVulnDBBuilt}} {
		if t := stateTime(ds, key.key); t != nil {
			add(key.desc, float64(t.Unix()))
		}
	}
	if t, err := c.s.Store.StateTime(ctx, store.StateInventorySync); err == nil && !t.IsZero() {
		add(descSync, float64(t.Unix())) // live: no-op syncs do not reload ds
	}
	now := time.Now()
	for _, e := range c.s.envInfos(ds) {
		env := e.Name
		ev := c.s.envView(ds, env, nil)
		sum := ev.summary
		if err := c.hist.observe(ctx, env, sum, now); err != nil {
			c.s.Log.Warn("history", "env", env, "err", err)
		}
		for sev, n := range sum.BySeverity {
			add(descVulns, float64(n), env, string(sev))
		}
		add(descKEV, float64(sum.KEV), env)
		add(descCritFix, float64(sum.CriticalFixable), env)
		for status, n := range map[string]int{"scanned": sum.Images.Scanned, "pending": sum.Images.Pending, "failed": sum.Images.Failed} {
			add(descImages, float64(n), env, status)
		}
		for _, w := range ev.workloads {
			for _, sev := range []model.Severity{model.Critical, model.High} {
				add(descWorkload, float64(w.Counts[sev]), env, w.Cluster, w.Namespace, w.Kind, w.Name, string(sev))
			}
			add(descWorkloadKEV, float64(w.KEV), env, w.Cluster, w.Namespace, w.Kind, w.Name)
		}
	}
	c.mu.Lock()
	c.last = metricsSnapshot{metrics: ms, at: time.Now()}
	c.mu.Unlock()
	return nil
}

func (c *collector) run(ctx context.Context, every time.Duration) {
	for {
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		if err := c.refresh(rctx); err != nil && ctx.Err() == nil {
			c.s.Log.Warn("metrics refresh", "err", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// MetricsHandler serves /metrics, refreshed in the background every 30 s
// until ctx ends (recording the history on the way). It is exposed on the
// internal port only, never through Pomerium.
func (s *Server) MetricsHandler(ctx context.Context) http.Handler {
	c := &collector{s: s, hist: &historian{s: s, every: cmp.Or(s.HistoryEvery, 5*time.Minute)}}
	go c.run(ctx, 30*time.Second)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c, collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
}
