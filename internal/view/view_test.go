package view

import (
	"testing"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

func ptr[T any](v T) *T { return &v }

func container(env, cluster, digest string) model.Container {
	return model.Container{
		Env:         env,
		WorkloadRef: model.WorkloadRef{Cluster: cluster, Namespace: "orders", Kind: "Deployment", Name: "api"},
		Container:   "api", Image: "ghcr.io/acme/api:" + digest, Digest: digest,
		FirstSeen: time.Now(),
	}
}

func row(vuln, pkg string, fixed ...string) model.FindingRow {
	return model.FindingRow{VulnID: vuln, Pkg: model.Package{Name: pkg, Version: "1", PURL: "pkg:x/" + pkg + "@1"}, FixedIn: fixed, FirstSeen: time.Now()}
}

func dataset() *model.Dataset {
	return &model.Dataset{
		Containers: []model.Container{
			container("prod", "prod-1", "old"),
			container("test", "test-1", "new"),
			container("dev", "dev-1", "pending"),
		},
		Findings: map[string][]model.FindingRow{
			"old": {row("CVE-1", "openssl", "3.0.15"), row("CVE-2", "zlib"), row("CVE-3", "curl", "8.1")},
			"new": {row("CVE-2", "zlib")},
		},
		Vulns: map[string]model.Vuln{
			"CVE-1": {ID: "CVE-1", Severity: model.Critical, KEV: ptr(false), EPSS: ptr(0.2)},
			"CVE-2": {ID: "CVE-2", Severity: model.Medium, KEV: ptr(false)},
			"CVE-3": {ID: "CVE-3", Severity: model.High, KEV: ptr(true)},
		},
		ImageStatus: map[string]string{"old": "scanned", "new": "scanned", "pending": "pending"},
	}
}

func TestFindingsPromotionAndOrder(t *testing.T) {
	fs := Findings(dataset(), "prod")
	if len(fs) != 3 {
		t.Fatalf("got %d findings", len(fs))
	}
	// KEV first, then severity.
	if fs[0].VulnID != "CVE-3" || fs[1].VulnID != "CVE-1" || fs[2].VulnID != "CVE-2" {
		t.Fatalf("order = %s %s %s", fs[0].VulnID, fs[1].VulnID, fs[2].VulnID)
	}
	// CVE-1 is gone in test: promote. The dev image is not scanned: no hint.
	if p := fs[1].Promotion; len(p) != 1 || p[0].Env != "test" || p[0].Digest != "new" {
		t.Errorf("CVE-1 promotion = %+v", p)
	}
	// CVE-2 is still in test: nothing to promote.
	if p := fs[2].Promotion; len(p) != 0 {
		t.Errorf("CVE-2 promotion = %+v", p)
	}
	if len(fs[1].Workloads) != 1 || fs[1].Workloads[0].Cluster != "prod-1" {
		t.Errorf("workloads = %+v", fs[1].Workloads)
	}
}

func TestSummaryAndWorkloads(t *testing.T) {
	ds := dataset()
	s := Summary(ds, "prod", Findings(ds, "prod"))
	if s.KEV != 1 || s.CriticalFixable != 1 || s.WorkloadsAffected != 1 || s.WorkloadsTotal != 1 || s.HighFixableInternet != 0 {
		t.Errorf("summary = %+v", s)
	}
	if s.BySeverity[model.Critical] != 1 || s.BySeverity[model.Medium] != 1 || s.BySeverity[model.Low] != 0 {
		t.Errorf("bySeverity = %+v", s.BySeverity)
	}
	if d := Summary(ds, "dev", nil); d.Images.Pending != 1 || d.Images.Total != 1 {
		t.Errorf("dev images = %+v", d.Images)
	}

	ws := Workloads(ds, "prod")
	if len(ws) != 1 || ws[0].KEV != 1 || ws[0].Fixable != 2 || ws[0].Counts[model.High] != 1 {
		t.Errorf("workloads = %+v", ws)
	}
}

func TestScope(t *testing.T) {
	ds := dataset()
	other := container("prod", "prod-1", "old")
	other.Namespace, other.Name = "shop", "storefront"
	ds.Containers = append(ds.Containers, other)

	if got := Scope(ds, nil, nil, nil); got != ds {
		t.Error("empty scope should return the dataset as is")
	}
	if s := Summary(Scope(ds, []string{"shop"}, nil, nil), "prod", Findings(Scope(ds, []string{"shop"}, nil, nil), "prod")); s.WorkloadsTotal != 1 {
		t.Errorf("ns scope: %d workloads", s.WorkloadsTotal)
	}
	// The promotion hint survives a workload scope: test runs the same workload.
	fs := Findings(Scope(ds, nil, []string{"orders/api"}, nil), "prod")
	for _, f := range fs {
		for _, w := range f.Workloads {
			if w.Namespace != "orders" {
				t.Errorf("out of scope workload %s/%s", w.Namespace, w.Name)
			}
		}
		if f.VulnID == "CVE-1" && len(f.Promotion) != 1 {
			t.Errorf("promotion lost under scope: %+v", f.Promotion)
		}
	}
	if len(Workloads(Scope(ds, []string{"nope"}, nil, nil), "prod")) != 0 {
		t.Error("unknown namespace should give no workloads")
	}
}

func TestFilter(t *testing.T) {
	fs := Findings(dataset(), "prod")
	n := 0
	for _, f := range fs {
		if (Filter{Severities: []model.Severity{model.Critical, model.High}, Fixable: true}).Match(f) {
			n++
		}
	}
	if n != 2 {
		t.Errorf("critical/high fixable = %d", n)
	}
	if !(Filter{Query: "OPENSSL"}).Match(fs[1]) || (Filter{Query: "nope"}).Match(fs[1]) {
		t.Error("query filter")
	}
}

func TestSuspect(t *testing.T) {
	for _, c := range []struct {
		pkg, version, image string
		want                bool
	}{
		{"traefik", "1.24.4", "123456789012.dkr.ecr.us-east-1.amazonaws.com/ghcr/acme/traefik:v3.4.1-patched", true},
		{"github.com/traefik/traefik/v3", "v3.4.2-0.20250601000000-0123456789ab", ".../traefik:v3.4.1-patched", false},
		{"traefik", "3.4.1", "traefik:v3.4.1@sha256:abc", false},
		{"openssl", "1.1.1", "traefik:v3.4.1", false},      // not named like the image
		{"traefik", "1.24.4", "traefik@sha256:abc", false}, // no tag to compare with
		{"Grafana", "10.4.0", "grafana/grafana:11.2.0", true},
	} {
		if got := Suspect(c.pkg, c.version, c.image); got != c.want {
			t.Errorf("Suspect(%s %s, %s) = %v", c.pkg, c.version, c.image, got)
		}
	}
}

func TestExceptions(t *testing.T) {
	ds := dataset()
	other := container("prod", "prod-1", "old")
	other.Namespace = "store"
	ds.Containers = append(ds.Containers, other)
	far := time.Now().Add(30 * 24 * time.Hour)

	// Limited to one namespace: the finding stays, without that workload.
	ds.Exceptions = []model.Exception{{ID: 1, VulnID: "CVE-1", Package: "openssl", Namespace: "orders", ExpiresAt: far}}
	f := findingByID(Findings(ds, "prod"), "CVE-1")
	if f.Exception != nil || len(f.Workloads) != 1 || f.Workloads[0].Namespace != "store" {
		t.Errorf("partial exception: exception=%v workloads=%+v", f.Exception, f.Workloads)
	}

	// Everywhere: the finding is excepted and left out of the counts.
	ds.Exceptions = []model.Exception{{ID: 2, VulnID: "CVE-1", Package: "openssl", ExpiresAt: far}}
	fs := Findings(ds, "prod")
	if f := findingByID(fs, "CVE-1"); f.Exception == nil || f.Exception.ID != 2 {
		t.Errorf("full exception not attached: %+v", f.Exception)
	}
	s := Summary(ds, "prod", fs)
	if s.Excepted != 1 || s.CriticalFixable != 0 || s.BySeverity[model.Critical] != 0 {
		t.Errorf("summary with exception: %+v", s)
	}
	if (Filter{}).Match(*findingByID(fs, "CVE-1")) || !(Filter{IncludeExcepted: true}).Match(*findingByID(fs, "CVE-1")) {
		t.Error("filter should hide excepted findings unless asked")
	}
	for _, w := range Workloads(ds, "prod") {
		if w.Counts[model.Critical] != 0 {
			t.Errorf("workload %s still counts the excepted critical", w.Name)
		}
	}
}

func findingByID(fs []model.Finding, id string) *model.Finding {
	for i := range fs {
		if fs[i].VulnID == id {
			return &fs[i]
		}
	}
	return &model.Finding{}
}

func TestExposureView(t *testing.T) {
	ds := dataset()
	public := container("prod", "prod-1", "old")
	public.Namespace, public.Name, public.Exposure = "web", "front", model.ExposureInternet
	ds.Containers = append(ds.Containers, public)

	fs := Findings(ds, "prod")
	if f := findingByID(fs, "CVE-1"); f.Exposure != model.ExposureInternet {
		t.Errorf("finding exposure = %s, want the widest of its workloads", f.Exposure)
	}
	if s := Summary(ds, "prod", fs); s.InternetAffected != 1 || s.WorkloadsAffected != 2 {
		t.Errorf("summary = %+v", s)
	}
	only := Scope(ds, nil, nil, []string{model.ExposureInternet})
	if ws := Workloads(only, "prod"); len(ws) != 1 || ws[0].Exposure != model.ExposureInternet {
		t.Errorf("internet scope workloads = %+v", ws)
	}
	if ws := Workloads(Scope(ds, nil, nil, []string{model.ExposureNone}), "prod"); len(ws) != 1 || ws[0].Name != "api" {
		t.Errorf("none scope workloads = %+v", ws)
	}
}

func TestKeepPromotions(t *testing.T) {
	hints := func(envs ...string) []model.PromotionHint {
		var out []model.PromotionHint
		for _, e := range envs {
			out = append(out, model.PromotionHint{Env: e})
		}
		return out
	}
	chain := []string{"dev", "test", "prod"}
	for _, tc := range []struct {
		env  string
		in   []model.PromotionHint
		want int
	}{
		{"prod", hints("dev", "test", "ops"), 2}, // ops is outside the chain
		{"test", hints("dev", "prod"), 1},        // prod would be a rollback
		{"dev", hints("test", "prod"), 0},
		{"ops", hints("dev"), 0},
	} {
		fs := []model.Finding{{Promotion: tc.in}}
		KeepPromotions(fs, tc.env, chain)
		if len(fs[0].Promotion) != tc.want {
			t.Errorf("%s: kept %+v, want %d", tc.env, fs[0].Promotion, tc.want)
		}
	}
	fs := []model.Finding{{Promotion: hints("prod")}}
	if KeepPromotions(fs, "dev", nil); len(fs[0].Promotion) != 1 {
		t.Error("an empty chain keeps every hint")
	}
}
