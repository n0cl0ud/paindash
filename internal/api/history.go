package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
)

const (
	historyDaily      = 24 * time.Hour // a point a day even when nothing moves
	historyMaxChanges = 20             // events kept to explain a point
)

// historian records the headline numbers of each env (counted like the
// summary tiles) into the history table: when they change, at most once per
// every and once the scans have settled, and at least once a day.
type historian struct {
	s       *Server
	every   time.Duration
	last    map[string]model.HistoryPoint // latest point written, per env
	waiting map[string]time.Time          // since when an env's numbers differ from its last point
}

func (h *historian) observe(ctx context.Context, env string, sum model.Summary, now time.Time) error {
	if h.last == nil {
		if done, _ := h.s.Store.State(ctx, store.StateExceptionMarkers); done != "1" {
			n, err := h.s.Store.PruneExceptionMarkers(ctx)
			if err == nil {
				err = h.s.Store.SetState(ctx, store.StateExceptionMarkers, "1")
			}
			if err != nil {
				h.s.Log.Warn("prune exception markers", "err", err)
			} else if n > 0 {
				h.s.Log.Info("exception markers pruned from history", "points", n)
			}
		}
		last, err := h.s.Store.LastHistory(ctx)
		if err != nil {
			return err
		}
		h.last, h.waiting = last, map[string]time.Time{}
	}
	p := model.HistoryPoint{At: now, KEV: sum.KEV, CriticalFixable: sum.CriticalFixable,
		HighFixableInternet: sum.HighFixableInternet, Excepted: sum.Excepted, Changes: []model.HistoryChange{}}
	last, ok := h.last[env]
	if ok && p.SameNumbers(last) {
		delete(h.waiting, env)
		if now.Sub(last.At) < historyDaily {
			return nil
		}
	} else {
		if _, w := h.waiting[env]; !w {
			h.waiting[env] = now
		}
		// Scans in progress mean numbers still moving: wait for them, a while.
		scanning := sum.Images.Pending > 0 && now.Sub(h.waiting[env]) < 12*h.every
		if scanning || ok && now.Sub(last.At) < h.every {
			return nil
		}
	}
	if ok {
		evs, err := h.s.Store.EventsSince(ctx, env, last.At, 1000)
		if err != nil {
			return err
		}
		p.Changes = historyChanges(evs)
	} else if h.s.HistoryBackfill != nil {
		for _, b := range h.s.HistoryBackfill(env, p) {
			if err := h.s.Store.AddHistory(ctx, env, b); err != nil {
				return err
			}
		}
	}
	if err := h.s.Store.AddHistory(ctx, env, p); err != nil {
		return err
	}
	h.last[env] = p
	delete(h.waiting, env)
	return nil
}

// historyChanges keeps the events that can move the numbers, latest last.
func historyChanges(evs []model.LiveEvent) []model.HistoryChange {
	out := []model.HistoryChange{}
	for _, ev := range evs {
		switch ev.Type {
		case model.EventDeployed, model.EventScanCompleted, model.EventVulnsNew, model.EventVulnsFixed:
			if ev.Delta == nil || ev.Delta.Added+ev.Delta.Removed == 0 {
				continue
			}
		case model.EventExceptionAdd, model.EventExceptionRev, model.EventExceptionExp:
			if ev.Env == model.AllEnvs {
				continue // covers nothing anywhere: moves no env's numbers
			}
		case model.EventRemoved, model.EventKEVAdded:
		default:
			continue
		}
		out = append(out, model.HistoryChange{At: ev.TS, Type: ev.Type, Title: ev.Title, Delta: ev.Delta})
	}
	if len(out) > historyMaxChanges {
		out = out[len(out)-historyMaxChanges:]
	}
	return out
}

// history serves the points of every env over the last ?days= (all when 0),
// each series ending with the live numbers so that it meets the tiles.
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	now := time.Now()
	var since time.Time
	if days, _ := strconv.Atoi(r.URL.Query().Get("days")); days > 0 {
		since = now.AddDate(0, 0, -days)
	}
	points, err := s.Store.History(r.Context(), since)
	if err != nil {
		s.fail(w, err)
		return
	}
	start, err := s.Store.HistoryStart(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, e := range s.envInfos(ds) {
		sum := s.envView(ds, e.Name, nil).summary
		points[e.Name] = append(points[e.Name], model.HistoryPoint{At: now, KEV: sum.KEV, CriticalFixable: sum.CriticalFixable,
			HighFixableInternet: sum.HighFixableInternet, Excepted: sum.Excepted, Changes: []model.HistoryChange{}})
	}
	if since.IsZero() {
		since = start
	}
	writeJSON(w, http.StatusOK, map[string]any{"since": since, "start": start, "now": now, "envs": points})
}
