package demo

import (
	"testing"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

func TestHistoryJoinsFirstPoint(t *testing.T) {
	first := model.HistoryPoint{At: time.Date(2026, 10, 22, 18, 0, 0, 0, time.UTC), KEV: 2, CriticalFixable: 9, HighFixableInternet: 3, Excepted: 1}
	for _, env := range []string{"prod", "test", "dev", "ops"} {
		ps := History(env, first, 60)
		if len(ps) < 10 {
			t.Fatalf("%s: only %d points", env, len(ps))
		}
		for i, p := range ps {
			if !p.At.Before(first.At) || i > 0 && p.At.Before(ps[i-1].At) {
				t.Fatalf("%s: point %d at %s out of order", env, i, p.At)
			}
			if p.KEV < 0 || p.CriticalFixable < 0 || p.HighFixableInternet < 0 || p.Excepted < 0 {
				t.Fatalf("%s: negative point %+v", env, p)
			}
		}
		if last := ps[len(ps)-1]; !last.SameNumbers(first) {
			t.Errorf("%s: last %+v does not join %+v", env, last, first)
		}
	}
}
