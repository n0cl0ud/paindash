package view

import (
	"fmt"
	"testing"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

// historyDataset: two envs, three namespaces, a sidecar whose traefik binary
// is misidentified next to real findings, rows with and without fixes, every
// exposure, and exceptions limited to a namespace or to a workload.
func historyDataset() *model.Dataset {
	at := func(env, ns, kind, name, ctr, image, digest, exposure string) model.Container {
		return model.Container{
			Env:         env,
			WorkloadRef: model.WorkloadRef{Cluster: env + "-1", Namespace: ns, Kind: kind, Name: name},
			Container:   ctr, Image: image, Digest: digest, Exposure: exposure, FirstSeen: time.Now(),
		}
	}
	r := func(vuln, pkg, version string, fixed ...string) model.FindingRow {
		return model.FindingRow{VulnID: vuln, Pkg: model.Package{Name: pkg, Version: version, Type: "deb"}, FixedIn: fixed}
	}
	far := time.Now().Add(30 * 24 * time.Hour)
	return &model.Dataset{
		Containers: []model.Container{
			at("prod", "shop", "Deployment", "web", "web", "ghcr.io/acme/web:1.2.0", "web", model.ExposureInternet),
			at("prod", "shop", "Deployment", "api", "api", "ghcr.io/acme/api:2.0.0", "api", model.ExposureInternal),
			at("prod", "edge", "Deployment", "proxy", "proxy", "ghcr.io/acme/proxy:3.1.0", "proxy", model.ExposureInternet),
			at("prod", "edge", "Deployment", "proxy", "traefik", "traefik:v3.4.1", "traefik3", model.ExposureInternet),
			at("prod", "ops", "Deployment", "ingress", "traefik", "traefik:v1.24.0", "traefik1", model.ExposureInternet),
			at("prod", "ops", "CronJob", "backup", "backup", "ghcr.io/acme/backup:1.0.0", "backup", ""),
			at("test", "shop", "Deployment", "web", "web", "ghcr.io/acme/web:1.3.0", "web2", model.ExposureInternet),
			at("test", "edge", "Deployment", "proxy", "proxy", "ghcr.io/acme/proxy:3.1.0", "proxy", model.ExposureInternal),
			at("test", "edge", "Deployment", "proxy", "traefik", "traefik:v3.4.1", "traefik3", model.ExposureInternal),
		},
		Findings: map[string][]model.FindingRow{
			"web":      {r("CVE-A", "openssl", "3.0.1", "3.0.15"), r("CVE-B", "zlib", "1.2.11", "1.2.13"), r("CVE-K", "curl", "7.8"), r("CVE-M", "libxml2", "2.9", "2.10"), r("CVE-L", "less", "5")},
			"api":      {r("CVE-A", "openssl", "3.0.2"), r("CVE-B", "zlib", "1.2.11", "1.2.13"), r("CVE-C", "busybox", "1.36", "1.37"), r("CVE-F", "sqlite", "3.40", "3.41")},
			"proxy":    {r("CVE-B", "zlib", "1.2.12", "1.2.13"), r("CVE-D", "nghttp2", "1.5", "1.6")},
			"traefik3": {r("CVE-T", "traefik", "1.24.4", "1.24.9"), r("CVE-K", "curl", "7.9", "8.0")},
			"traefik1": {r("CVE-T", "traefik", "1.24.4", "1.24.9")},
			"backup":   {r("CVE-B", "zlib", "1.2.11"), r("CVE-E", "glibc", "2.36", "2.37"), r("CVE-K", "curl", "7.8"), r("CVE-F", "sqlite", "3.39")},
			"web2":     {r("CVE-A", "openssl", "3.0.15"), r("CVE-B", "zlib", "1.2.13", "1.3")},
		},
		Vulns: map[string]model.Vuln{
			"CVE-A": {ID: "CVE-A", Severity: model.Critical, KEV: ptr(false)},
			"CVE-B": {ID: "CVE-B", Severity: model.High, KEV: ptr(false)},
			"CVE-C": {ID: "CVE-C", Severity: model.Critical, KEV: ptr(false)},
			"CVE-D": {ID: "CVE-D", Severity: model.High, KEV: ptr(false)},
			"CVE-E": {ID: "CVE-E", Severity: model.Critical, KEV: ptr(false)},
			"CVE-F": {ID: "CVE-F", Severity: model.Critical, KEV: ptr(false)},
			"CVE-K": {ID: "CVE-K", Severity: model.High, KEV: ptr(true)},
			"CVE-L": {ID: "CVE-L", Severity: model.Low, KEV: ptr(false)},
			"CVE-M": {ID: "CVE-M", Severity: model.Medium, KEV: ptr(false)},
			"CVE-T": {ID: "CVE-T", Severity: model.High, KEV: ptr(false)},
		},
		ImageStatus: map[string]string{"web": "scanned", "api": "scanned", "proxy": "scanned", "traefik3": "scanned", "traefik1": "scanned", "backup": "scanned", "web2": "scanned"},
		Exceptions: []model.Exception{
			{ID: 1, VulnID: "CVE-B", Package: "zlib", Namespace: "shop", ExpiresAt: far},
			{ID: 2, VulnID: "CVE-E", Package: "glibc", Workload: "backup", ExpiresAt: far},
			{ID: 3, VulnID: "CVE-D", Package: "nghttp2", Workload: "proxy", ExpiresAt: far},
			{ID: 4, VulnID: "CVE-M", Package: "libxml2", Namespace: "shop", ExpiresAt: far},
			// Covers the only container of CVE-F with a fix: the fix still counts.
			{ID: 5, VulnID: "CVE-F", Package: "sqlite", Namespace: "shop", ExpiresAt: far},
		},
	}
}

func TestCountFactsMatchesSummary(t *testing.T) {
	ds := historyDataset()
	type scope struct{ ns, wl, exp []string }
	scopes := []scope{
		{},
		{ns: []string{"shop"}},
		{ns: []string{"edge"}},
		{ns: []string{"ops"}},
		{ns: []string{"edge", "shop"}},
		{wl: []string{"shop/web"}},
		{wl: []string{"edge/proxy"}},
		{wl: []string{"ops/ingress"}},
		{wl: []string{"ops/backup", "shop/api"}},
		{exp: []string{model.ExposureInternet}},
		{exp: []string{model.ExposureInternal}},
		{exp: []string{model.ExposureNone}},
		{exp: []string{model.ExposureInternet, model.ExposureNone}},
		{ns: []string{"shop"}, exp: []string{model.ExposureInternet}},
		{ns: []string{"edge", "ops"}, wl: []string{"edge/proxy", "ops/backup"}},
		{ns: []string{"ops", "shop"}, exp: []string{model.ExposureInternal, model.ExposureNone}},
		{wl: []string{"nope/nothing"}},
	}
	var seen [4]bool
	for _, env := range []string{"prod", "test"} {
		facts := HistoryFacts(ds, env)
		for _, sc := range scopes {
			sds := Scope(ds, sc.ns, sc.wl, sc.exp)
			sum := Summary(sds, env, Findings(sds, env))
			var in []model.HistoryFact
			for _, f := range facts {
				if InScope(f, sc.ns, sc.wl, sc.exp) {
					in = append(in, f)
				}
			}
			kev, crit, high, exc := CountFacts(in)
			got := [4]int{kev, crit, high, exc}
			want := [4]int{sum.KEV, sum.CriticalFixable, sum.HighFixableInternet, sum.Excepted}
			if got != want {
				t.Errorf("%s %+v: facts count kev/crit/high/excepted %v, summary %v", env, sc, got, want)
			}
			for i, n := range got {
				seen[i] = seen[i] || n > 0
			}
		}
	}
	if seen != [4]bool{true, true, true, true} {
		t.Errorf("every number should be non-zero for some scope: %v", seen)
	}

	// The misidentified sidecar hides CVE-T everywhere it is in scope; alone,
	// the ingress counts it.
	in := func(ns ...string) []model.HistoryFact {
		var out []model.HistoryFact
		for _, f := range HistoryFacts(ds, "prod") {
			if InScope(f, ns, nil, nil) {
				out = append(out, f)
			}
		}
		return out
	}
	if _, _, high, _ := CountFacts(in("ops")); high != 1 {
		t.Errorf("ops: high with fix, internet = %d, want CVE-T", high)
	}
	if _, _, high, _ := CountFacts(in("edge", "ops")); high != 2 {
		t.Errorf("edge and ops: high with fix, internet = %d, want CVE-B and CVE-K, not CVE-T", high)
	}
}

func TestHistoryFacts(t *testing.T) {
	ds := historyDataset()
	facts := HistoryFacts(ds, "prod")
	for _, f := range facts {
		if f.VulnID == "CVE-L" {
			t.Error("a low vulnerability without exception can never count: not a fact")
		}
	}
	got := map[string]model.HistoryFact{}
	for _, f := range facts {
		got[fmt.Sprintf("%s %s/%s", f.VulnID, f.Namespace, f.Name)] = f
	}
	if f := got["CVE-M shop/web"]; !f.Covered {
		t.Errorf("a covered medium is kept for the excepted count: %+v", f)
	}
	if f := got["CVE-K edge/proxy"]; !f.HasFix || f.Exposure != model.ExposureInternet || f.Suspect {
		t.Errorf("CVE-K on the proxy sidecar: %+v", f)
	}
	if f := got["CVE-T edge/proxy"]; !f.Suspect {
		t.Errorf("CVE-T on the proxy sidecar should be suspect: %+v", f)
	}
	if f := got["CVE-T ops/ingress"]; f.Suspect {
		t.Errorf("CVE-T on the ingress is right: %+v", f)
	}
	if f := got["CVE-E ops/backup"]; !f.Covered || f.Exposure != model.ExposureNone {
		t.Errorf("CVE-E on backup: %+v", f)
	}
	// Deterministic: the same facts in the same order, whatever the container order.
	ds.Containers[0], ds.Containers[5] = ds.Containers[5], ds.Containers[0]
	again := HistoryFacts(ds, "prod")
	if len(again) != len(facts) {
		t.Fatalf("%d facts, then %d", len(facts), len(again))
	}
	for i := range facts {
		if facts[i] != again[i] {
			t.Errorf("fact %d: %+v, then %+v", i, facts[i], again[i])
		}
	}
}
