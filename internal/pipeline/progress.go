package pipeline

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
	"github.com/n0cl0ud/paindash/internal/view"
)

// initialProgressLoop keeps every env's live feed moving during the initial
// scan, whose per-image events are silenced: one progress event per env and
// period, when its scanned count changed.
func (w *Worker) initialProgressLoop(ctx context.Context) {
	every := w.ProgressEvery
	if every <= 0 {
		every = time.Minute
	}
	last := map[string]int{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if done, err := w.Store.State(ctx, store.StateInitialScan); err != nil || done != "" {
			if done != "" {
				return
			}
			continue
		}
		ds, err := w.Store.Dataset(ctx)
		if err != nil {
			continue
		}
		for _, env := range envsOf(ds) {
			s := view.Summary(ds, env, view.Findings(ds, env))
			if s.Images.Scanned == last[env] || s.Images.Total == 0 {
				continue
			}
			last[env] = s.Images.Scanned
			w.Emit.Emit(ctx, model.LiveEvent{
				Env:      env,
				Cluster:  clusterOf(ds, env),
				Type:     model.EventScanCompleted,
				Title:    progressTitle(s),
				Severity: worstSeverity(s.BySeverity),
				Delta:    &model.Delta{Added: s.BySeverity[model.Critical] + s.BySeverity[model.High], KEV: s.KEV},
			})
		}
	}
}

func progressTitle(s model.Summary) string {
	t := fmt.Sprintf("Initial scan: %d/%d images scanned", s.Images.Scanned, s.Images.Total)
	if s.Images.Failed > 0 {
		t += fmt.Sprintf(" (%d failed)", s.Images.Failed)
	}
	return t + fmt.Sprintf(" · %d KEV, %d critical with a fix", s.KEV, s.CriticalFixable)
}

func worstSeverity(counts map[model.Severity]int) *model.Severity {
	for _, sev := range model.Severities {
		if counts[sev] > 0 {
			s := sev
			return &s
		}
	}
	return nil
}

func envsOf(ds *model.Dataset) []string {
	seen := map[string]bool{}
	var envs []string
	for _, c := range ds.Containers {
		if !seen[c.Env] {
			seen[c.Env] = true
			envs = append(envs, c.Env)
		}
	}
	sort.Strings(envs)
	return envs
}

func clusterOf(ds *model.Dataset, env string) string {
	for _, c := range ds.Containers {
		if c.Env == env {
			return c.Cluster
		}
	}
	return ""
}
