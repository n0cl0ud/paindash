package pipeline

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/n0cl0ud/paindash/internal/enrich"
	"github.com/n0cl0ud/paindash/internal/live"
	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
)

// Enricher keeps KEV flags and EPSS scores up to date. A vuln entering the
// KEV catalog is the most urgent signal there is, so it is announced live.
type Enricher struct {
	Client    *enrich.Client
	Store     *store.Store
	Hub       *live.Hub
	Emit      *Emitter
	KEVEvery  time.Duration
	EPSSEvery time.Duration
	Log       *slog.Logger

	mu  sync.Mutex
	kev map[string]time.Time
}

func (e *Enricher) Run(ctx context.Context) {
	var lastEPSS time.Time
	for {
		if err := e.refreshKEV(ctx); err != nil && ctx.Err() == nil {
			e.Log.Warn("KEV refresh failed", "err", err)
		}
		if time.Since(lastEPSS) >= e.EPSSEvery {
			if err := e.refreshEPSS(ctx); err != nil && ctx.Err() == nil {
				e.Log.Warn("EPSS refresh failed", "err", err)
			} else {
				lastEPSS = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(e.KEVEvery):
		}
	}
}

func (e *Enricher) refreshKEV(ctx context.Context) error {
	catalog, err := e.Client.KEV(ctx)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.kev = catalog
	e.mu.Unlock()

	newly, err := e.Store.MarkKEV(ctx, catalog)
	if err != nil {
		return err
	}
	loaded, err := e.Store.State(ctx, store.StateKEVLoaded)
	if err != nil {
		return err
	}
	if loaded == "" {
		// First load flags every known vuln at once: not news.
		return e.Store.SetStateTime(ctx, store.StateKEVLoaded, time.Now())
	}
	for _, id := range newly {
		announceKEV(ctx, e.Store, e.Emit, id)
	}
	if len(newly) > 0 {
		e.Hub.Invalidate(model.AllEnvs)
	}
	return nil
}

func (e *Enricher) refreshEPSS(ctx context.Context) error {
	ids, err := e.Store.CVEIDs(ctx)
	if err != nil {
		return err
	}
	scores, err := e.Client.EPSS(ctx, ids)
	if err := e.Store.SetEPSS(ctx, scores); err != nil {
		return err
	}
	e.Hub.Invalidate(model.AllEnvs)
	return err
}

// Apply enriches vulns that were just discovered by a scan.
func (e *Enricher) Apply(ctx context.Context, ids []string) {
	var cves []string
	kev := map[string]time.Time{}
	e.mu.Lock()
	for _, id := range ids {
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		cves = append(cves, id)
		if t, ok := e.kev[id]; ok {
			kev[id] = t
		}
	}
	e.mu.Unlock()
	if len(cves) == 0 {
		return
	}
	if _, err := e.Store.MarkKEV(ctx, kev); err != nil {
		e.Log.Warn("apply KEV", "err", err)
	}
	scores, err := e.Client.EPSS(ctx, cves)
	if err != nil {
		e.Log.Warn("apply EPSS", "err", err)
	}
	if err := e.Store.SetEPSS(ctx, scores); err != nil {
		e.Log.Warn("store EPSS", "err", err)
	}
}
