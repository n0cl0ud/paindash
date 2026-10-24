package demo

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

// promotionLag is how many days after dev a release reaches each env.
var promotionLag = map[string]int{"dev": 0, "test": 1, "prod": 4, "ops": 0}

type historyStep struct {
	at                   time.Time
	kev, crit, high, exc int // effect on the numbers
	changes              []model.HistoryChange
}

// History invents the days before an env's first real point, so the demo's
// chart has a past: releases reach dev, then test a day later and prod four
// days later; vulnerability DB updates hit every env the same day. The values
// are computed backwards from first, so the series joins it.
func History(env string, first model.HistoryPoint, days int) []model.HistoryPoint {
	r := rand.New(rand.NewPCG(hash("history"), 7)) // same schedule for every env
	day0 := first.At.Truncate(24*time.Hour).AddDate(0, 0, -days)
	var steps []historyStep
	for d := 0; d < days; d++ {
		day := day0.AddDate(0, 0, d)
		// Vulnerability DB update, every env.
		if r.Float64() < 0.55 {
			s := historyStep{at: day.Add(6*time.Hour + time.Duration(r.IntN(60))*time.Minute),
				crit: r.IntN(4), high: r.IntN(3)}
			if r.Float64() < 0.12 {
				s.kev = 1
			}
			steps = append(steps, dbStep(s, r))
		}
		// A release, promoted from dev to prod.
		if r.Float64() < 0.5 && day.Weekday() != time.Saturday && day.Weekday() != time.Sunday {
			pool := releasable(env == "ops")
			wl := pool[r.IntN(len(pool))]
			s := historyStep{at: day.AddDate(0, 0, promotionLag[env]).Add(time.Duration(9+r.IntN(8)) * time.Hour),
				crit: -(1 + r.IntN(5)), high: -r.IntN(3)}
			if env == "ops" { // fewer, smaller platform releases
				s.crit, s.high = -r.IntN(3), -r.IntN(2)
			}
			if r.Float64() < 0.2 {
				s.kev = -1
			}
			version := fmt.Sprintf("v%d.%d.%d", 1+r.IntN(3), r.IntN(20), r.IntN(10))
			if s.at.Before(first.At) {
				steps = append(steps, releaseStep(s, wl, version, r))
			}
		}
		// An exception now and then, per env, back in the lists when it expires.
		if er := rand.New(rand.NewPCG(hash(env), uint64(d))); er.Float64() < 0.07 {
			id := fmt.Sprintf("CVE-2099-%04d", 1000+er.IntN(9000))
			added := historyStep{at: day.Add(15 * time.Hour), exc: 1, crit: -1}
			expired := historyStep{at: added.at.AddDate(0, 0, 10+er.IntN(30)), exc: -1, crit: 1}
			if expired.at.Before(first.At) {
				added.changes = []model.HistoryChange{{At: added.at, Type: model.EventExceptionAdd,
					Title: fmt.Sprintf("Exception added: %s in openssl (namespace checkout), until %s (demo)", id, expired.at.Format("Jan 2, 2006"))}}
				expired.changes = []model.HistoryChange{{At: expired.at, Type: model.EventExceptionExp,
					Title: fmt.Sprintf("Exception expired: %s in openssl (namespace checkout) is back in the lists", id)}}
				steps = append(steps, added, expired)
			}
		}
	}
	sort.Slice(steps, func(i, j int) bool { return steps[i].at.Before(steps[j].at) })

	// Walk back from first: the state before a step is the one after it minus
	// its effect, never below zero.
	cur := first
	points := make([]model.HistoryPoint, len(steps))
	for i := len(steps) - 1; i >= 0; i-- {
		s := steps[i]
		points[i] = model.HistoryPoint{At: s.at, KEV: cur.KEV, CriticalFixable: cur.CriticalFixable,
			HighFixableInternet: cur.HighFixableInternet, Excepted: cur.Excepted, Changes: s.changes}
		cur.KEV = max(0, cur.KEV-s.kev)
		cur.CriticalFixable = max(0, cur.CriticalFixable-s.crit)
		cur.HighFixableInternet = max(0, cur.HighFixableInternet-s.high)
		cur.Excepted = max(0, cur.Excepted-s.exc)
	}
	start := cur
	start.At, start.Changes = day0, []model.HistoryChange{}
	return append([]model.HistoryPoint{start}, points...)
}

func dbStep(s historyStep, r *rand.Rand) historyStep {
	n := s.crit + s.high + r.IntN(4)
	if n == 0 {
		return s
	}
	s.changes = append(s.changes, model.HistoryChange{At: s.at, Type: model.EventVulnsNew,
		Title: fmt.Sprintf("New CVEs published: %d vulnerabilities on %d workloads (%d critical, %d high)", n, 1+r.IntN(4), s.crit, s.high),
		Delta: &model.Delta{Added: n, KEV: s.kev}})
	if s.kev > 0 {
		s.changes = append(s.changes, model.HistoryChange{At: s.at, Type: model.EventKEVAdded,
			Title: fmt.Sprintf("CVE-2099-%04d added to the KEV catalog (actively exploited): 2 workloads affected", 1000+r.IntN(9000))})
	}
	return s
}

func releaseStep(s historyStep, wl workload, version string, r *rand.Rand) historyStep {
	n := -s.crit - s.high + r.IntN(4)
	s.changes = []model.HistoryChange{{At: s.at, Type: model.EventScanCompleted,
		Title: fmt.Sprintf("%s/%s (%s) scanned: +0 / −%d vulnerabilities vs previous version", wl.ns, wl.name, version, n),
		Delta: &model.Delta{Removed: n}}}
	return s
}

func releasable(ops bool) []workload {
	var out []workload
	for _, w := range workloads {
		if (len(w.envs) == 1) == ops || ops && len(w.envs) == len(allEnvs) {
			out = append(out, w)
		}
	}
	return out
}
