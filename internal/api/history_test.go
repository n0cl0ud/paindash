package api

import (
	"testing"

	"github.com/n0cl0ud/paindash/internal/model"
)

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
