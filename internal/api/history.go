package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
	"github.com/n0cl0ud/paindash/internal/view"
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

// factRecorder keeps the history facts (what the numbers are made of) as
// validity intervals, so that /api/history can recount the numbers of any
// scope. Only changes are written.
type factRecorder struct {
	s     *Server
	every time.Duration
	open  map[model.HistoryFact]int64 // facts that hold, by row id; nil until loaded
	ds    *model.Dataset              // dataset of the last recording
	held  map[string]time.Time        // since when an env has had pending scans
	// skipped: envs left untouched last time, to look at again once their
	// hold ends, even if the dataset has not changed.
	skipped map[string]bool
}

// record brings the open facts of every env in line with ds. pending tells
// which envs have scans in progress: their facts are left as they are for a
// while, or a rollout would make the numbers dip until the new image is scanned.
func (r *factRecorder) record(ctx context.Context, ds *model.Dataset, pending map[string]bool, now time.Time) error {
	if r.open == nil {
		open, dups, err := r.s.Store.OpenHistoryFacts(ctx)
		if err != nil {
			return err
		}
		if len(dups) > 0 {
			if _, err := r.s.Store.UpdateHistoryFacts(ctx, dups, nil, now); err != nil {
				return err
			}
		}
		r.open, r.held = open, map[string]time.Time{}
	}
	changed := ds != r.ds
	if !changed && len(r.skipped) == 0 {
		return nil
	}
	envs := map[string]bool{}
	for env := range pending {
		envs[env] = true
	}
	for f := range r.open {
		envs[f.Env] = true // an env gone from the inventory closes its facts
	}
	skipped := map[string]bool{}
	var closed []int64
	var opened []model.HistoryFact
	for env := range envs {
		if !pending[env] {
			delete(r.held, env)
		} else {
			if _, ok := r.held[env]; !ok {
				r.held[env] = now
			}
			if now.Sub(r.held[env]) < 12*r.every {
				skipped[env] = true
				continue
			}
		}
		if !changed && !r.skipped[env] {
			continue // nothing moved there
		}
		current := map[model.HistoryFact]bool{}
		for _, f := range view.HistoryFacts(ds, env) {
			current[f] = true
			if _, ok := r.open[f]; !ok {
				opened = append(opened, f)
			}
		}
		for f, id := range r.open {
			if f.Env == env && !current[f] {
				closed = append(closed, id)
			}
		}
	}
	if len(closed) > 0 || len(opened) > 0 {
		ids, err := r.s.Store.UpdateHistoryFacts(ctx, closed, opened, now)
		if err != nil {
			return err
		}
		gone := map[int64]bool{}
		for _, id := range closed {
			gone[id] = true
		}
		for f, id := range r.open {
			if gone[id] {
				delete(r.open, f)
			}
		}
		for i, f := range opened {
			r.open[f] = ids[i]
		}
	}
	r.ds, r.skipped = ds, skipped
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
// each series ending with the live numbers so that it meets the tiles. Under a
// scope (?ns=, ?wl=, ?exp=), the points are recounted from the history facts,
// which begin at scopedSince.
func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	ds, ok := s.load(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	now := time.Now()
	var since time.Time
	if days, _ := strconv.Atoi(q.Get("days")); days > 0 {
		since = now.AddDate(0, 0, -days)
	}
	start, err := s.Store.HistoryStart(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	ns, wl, exp := csv(q.Get("ns")), csv(q.Get("wl")), csv(q.Get("exp"))
	var points map[string][]model.HistoryPoint
	var scopedSince map[string]time.Time
	if len(ns) == 0 && len(wl) == 0 && len(exp) == 0 {
		if points, err = s.Store.History(r.Context(), since); err != nil {
			s.fail(w, err)
			return
		}
	} else {
		points, scopedSince = map[string][]model.HistoryPoint{}, map[string]time.Time{}
		in := func(f model.HistoryFact) bool { return view.InScope(f, ns, wl, exp) }
		for _, e := range s.envInfos(ds) {
			spans, first, err := s.Store.HistoryFactsSince(r.Context(), e.Name, since)
			if err != nil {
				s.fail(w, err)
				return
			}
			if first.IsZero() {
				points[e.Name] = []model.HistoryPoint{} // nothing recorded yet: no live point either
				continue
			}
			scopedSince[e.Name] = first
			points[e.Name] = scopedHistory(spans, first, since, now, in)
		}
	}
	for _, e := range s.envInfos(ds) {
		if scopedSince != nil && scopedSince[e.Name].IsZero() {
			continue
		}
		sum := s.envView(ds, e.Name, q).summary
		points[e.Name] = append(points[e.Name], model.HistoryPoint{At: now, KEV: sum.KEV, CriticalFixable: sum.CriticalFixable,
			HighFixableInternet: sum.HighFixableInternet, Excepted: sum.Excepted, Changes: []model.HistoryChange{}})
	}
	if since.IsZero() {
		since = start
	}
	writeJSON(w, http.StatusOK, map[string]any{"since": since, "start": start, "now": now, "envs": points, "scopedSince": scopedSince})
}

// scopedHistory recounts the numbers of the facts in scope over the window: a
// point at its start (the later of since and first, when the facts begin),
// then one at each change before now that moves them. These points carry no
// change markers: events are not recorded per scope.
func scopedHistory(spans []store.FactSpan, first, since, now time.Time, in func(model.HistoryFact) bool) []model.HistoryPoint {
	type change struct {
		at   time.Time
		fact model.HistoryFact
		d    int
	}
	var changes []change
	for _, sp := range spans {
		if !in(sp.Fact) {
			continue
		}
		changes = append(changes, change{sp.Since, sp.Fact, 1})
		if !sp.Until.IsZero() {
			changes = append(changes, change{sp.Until, sp.Fact, -1})
		}
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].at.Before(changes[j].at) })

	active := map[model.HistoryFact]int{}
	apply := func(c change) {
		if active[c.fact] += c.d; active[c.fact] <= 0 {
			delete(active, c.fact)
		}
	}
	point := func(at time.Time) model.HistoryPoint {
		facts := make([]model.HistoryFact, 0, len(active))
		for f := range active {
			facts = append(facts, f)
		}
		kev, crit, high, exc := view.CountFacts(facts)
		return model.HistoryPoint{At: at, KEV: kev, CriticalFixable: crit, HighFixableInternet: high, Excepted: exc,
			Changes: []model.HistoryChange{}}
	}

	from := since
	if first.After(from) {
		from = first
	}
	i := 0
	for ; i < len(changes) && !changes[i].at.After(from); i++ {
		apply(changes[i])
	}
	out := []model.HistoryPoint{point(from)}
	for i < len(changes) && changes[i].at.Before(now) {
		at := changes[i].at
		for ; i < len(changes) && changes[i].at.Equal(at); i++ {
			apply(changes[i])
		}
		if p := point(at); !p.SameNumbers(out[len(out)-1]) {
			out = append(out, p)
		}
	}
	return out
}
