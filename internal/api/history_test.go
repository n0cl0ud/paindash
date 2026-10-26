package api

import (
	"testing"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/store"
	"github.com/n0cl0ud/paindash/internal/view"
)

func TestScopedHistory(t *testing.T) {
	t0 := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	h := func(n float64) time.Time { return t0.Add(time.Duration(n * float64(time.Hour))) }
	fact := func(ns, vuln string, sev model.Severity, kev bool, exposure string) model.HistoryFact {
		return model.HistoryFact{Env: "prod", WorkloadRef: model.WorkloadRef{Cluster: "prod-1", Namespace: ns, Kind: "Deployment", Name: "app"},
			VulnID: vuln, PkgName: "pkg-" + vuln, PkgType: "deb", Severity: sev, KEV: kev, HasFix: true, Exposure: exposure}
	}
	high := fact("shop", "CVE-H", model.High, false, model.ExposureInternet)
	highInternal := high
	highInternal.Exposure = model.ExposureInternal
	crit := fact("ops", "CVE-C", model.Critical, false, model.ExposureNone)
	kev := fact("shop", "CVE-K", model.Medium, true, model.ExposureNone)
	medium := fact("shop", "CVE-M", model.Medium, false, model.ExposureInternet)
	outside := fact("dev", "CVE-X", model.Critical, true, model.ExposureInternet)
	spans := []store.FactSpan{
		{Fact: high, Since: h(0), Until: h(2)},
		{Fact: outside, Since: h(0)},
		{Fact: medium, Since: h(0.5)}, // moves no number: no point
		{Fact: crit, Since: h(1)},
		{Fact: highInternal, Since: h(2)}, // the exposure changed
		{Fact: kev, Since: h(3), Until: h(4)},
		{Fact: crit, Since: h(4), Until: h(9)}, // a duplicate span: counted once
		{Fact: outside, Since: h(5), Until: h(6)},
		{Fact: kev, Since: h(10)}, // after now
	}
	in := func(f model.HistoryFact) bool { return view.InScope(f, []string{"ops", "shop"}, nil, nil) }
	type pt struct {
		at                   time.Time
		kev, crit, high, exc int
	}
	check := func(name string, got []model.HistoryPoint, want []pt) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %d points, want %d: %+v", name, len(got), len(want), got)
		}
		for i, w := range want {
			g := got[i]
			if !g.At.Equal(w.at) || g.KEV != w.kev || g.CriticalFixable != w.crit || g.HighFixableInternet != w.high || g.Excepted != w.exc {
				t.Errorf("%s: point %d = %s %d/%d/%d/%d, want %s %d/%d/%d/%d", name, i,
					g.At.Format(time.TimeOnly), g.KEV, g.CriticalFixable, g.HighFixableInternet, g.Excepted,
					w.at.Format(time.TimeOnly), w.kev, w.crit, w.high, w.exc)
			}
			if g.Changes == nil || len(g.Changes) != 0 {
				t.Errorf("%s: point %d has change markers %v", name, i, g.Changes)
			}
		}
	}
	now := h(8)

	// The window starts before the facts: the series starts with them.
	check("before", scopedHistory(spans, h(0), h(-24), now, in), []pt{
		{h(0), 0, 0, 1, 0},
		{h(1), 0, 1, 1, 0},
		{h(2), 0, 1, 0, 0},
		{h(3), 1, 1, 0, 0},
		{h(4), 0, 1, 0, 0},
	})
	// The window starts later: what held then, then the changes after it.
	check("after", scopedHistory(spans, h(0), h(2.5), now, in), []pt{
		{h(2.5), 0, 1, 0, 0},
		{h(3), 1, 1, 0, 0},
		{h(4), 0, 1, 0, 0},
	})
	// Starting on a change instant applies it.
	check("on a change", scopedHistory(spans, h(0), h(3), now, in), []pt{
		{h(3), 1, 1, 0, 0},
		{h(4), 0, 1, 0, 0},
	})
	// Nothing in scope: one point of zeros at the start.
	none := func(model.HistoryFact) bool { return false }
	check("empty scope", scopedHistory(spans, h(0), h(-24), now, none), []pt{{h(0), 0, 0, 0, 0}})
}

func TestHistoryChanges(t *testing.T) {
	evs := []model.LiveEvent{
		{Type: model.EventScanCompleted, Title: "a scanned: +0 / −19", Delta: &model.Delta{Removed: 19}},
		{Type: model.EventScanCompleted, Title: "b scanned: +0 / −0", Delta: &model.Delta{}},
		{Type: model.EventDeployed, Title: "c deployed, scan pending"},
		{Type: model.EventDBUpdated, Title: "DB updated"},
		{Type: model.EventVulnsNew, Title: "New CVEs published", Delta: &model.Delta{Added: 3}},
		{Env: "prod", Type: model.EventExceptionAdd, Title: "Exception added"},
		{Env: model.AllEnvs, Type: model.EventExceptionAdd, Title: "Exception covering nothing"},
		{Type: model.EventScanFailed, Title: "d failed"},
	}
	got := historyChanges(evs)
	want := []string{"a scanned: +0 / −19", "New CVEs published", "Exception added"}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i, c := range got {
		if c.Title != want[i] {
			t.Errorf("change %d = %q, want %q", i, c.Title, want[i])
		}
	}

	many := make([]model.LiveEvent, 30)
	for i := range many {
		many[i] = model.LiveEvent{Type: model.EventRemoved, Title: string(rune('A' + i))}
	}
	if got := historyChanges(many); len(got) != historyMaxChanges || got[len(got)-1].Title != many[29].Title {
		t.Errorf("cap keeps the latest: %d, last %q", len(got), got[len(got)-1].Title)
	}
}
