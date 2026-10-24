// Package pipeline runs paindash's background loops: inventory sync, image
// scanning, DB refresh rematching and enrichment. Each loop turns what changed
// into live events for the UI.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sort"

	"github.com/n0cl0ud/paindash/internal/live"
	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
)

// Emitter persists an event, then pushes it to connected browsers.
type Emitter struct {
	Store *store.Store
	Hub   *live.Hub
	Log   *slog.Logger
}

func (e *Emitter) Emit(ctx context.Context, ev model.LiveEvent) {
	if err := e.Store.AddEvent(ctx, &ev); err != nil {
		e.Log.Error("store event", "err", err, "type", ev.Type)
		return
	}
	e.Hub.Publish(&ev)
}

// announceKEV tells every env running a vuln that it entered the KEV catalog.
func announceKEV(ctx context.Context, st *store.Store, em *Emitter, vulnID string) {
	containers, err := st.ContainersForVuln(ctx, vulnID)
	if err != nil || len(containers) == 0 {
		return
	}
	refs, err := st.VulnRefs(ctx, []string{vulnID})
	if err != nil {
		return
	}
	sev := refs[vulnID].Severity
	for env, cs := range byEnv(containers) {
		wl := workloads(cs)
		em.Emit(ctx, model.LiveEvent{
			Env:      env,
			Cluster:  cs[0].Cluster,
			Type:     model.EventKEVAdded,
			Title:    fmt.Sprintf("%s added to the KEV catalog (actively exploited): %s affected", vulnID, plural(len(wl), "workload", "workloads")),
			Severity: &sev,
			Workload: workloadIfSingle(wl),
			Delta:    &model.Delta{KEV: 1},
		})
	}
}

func byEnv(cs []model.Container) map[string][]model.Container {
	m := map[string][]model.Container{}
	for _, c := range cs {
		m[c.Env] = append(m[c.Env], c)
	}
	return m
}

// workloads returns the distinct workloads of containers, in a stable order.
func workloads(cs []model.Container) []model.WorkloadRef {
	seen := map[string]bool{}
	var out []model.WorkloadRef
	for _, c := range cs {
		if k := c.WorkloadRef.Key(); !seen[k] {
			seen[k] = true
			out = append(out, c.WorkloadRef)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

func workloadIfSingle(wl []model.WorkloadRef) *model.WorkloadRef {
	if len(wl) == 1 {
		return &wl[0]
	}
	return nil
}

func maxSeverity(vulns []model.VulnRef) *model.Severity {
	var best *model.Severity
	for _, v := range vulns {
		if best == nil || v.Severity.Rank() > best.Rank() {
			s := v.Severity
			best = &s
		}
	}
	return best
}

func countKEV(vulns []model.VulnRef) int {
	n := 0
	for _, v := range vulns {
		if v.KEV {
			n++
		}
	}
	return n
}

// severityPhrase summarizes vulns: "2 critical, 5 high".
func severityPhrase(vulns []model.VulnRef) string {
	var crit, high int
	for _, v := range vulns {
		switch v.Severity {
		case model.Critical:
			crit++
		case model.High:
			high++
		}
	}
	switch {
	case len(vulns) == 0:
		return "no vulnerabilities"
	case crit == 0 && high == 0:
		return plural(len(vulns), "vulnerability", "vulnerabilities") + ", none critical or high"
	case crit == 0:
		return fmt.Sprintf("%d high", high)
	case high == 0:
		return fmt.Sprintf("%d critical", crit)
	}
	return fmt.Sprintf("%d critical, %d high", crit, high)
}

func cond(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
