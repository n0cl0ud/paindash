package view

import (
	"slices"
	"sort"

	"github.com/n0cl0ud/paindash/internal/model"
)

// HistoryFacts lists what the history numbers of env are made of: one fact per
// (vulnerability, package, workload), aggregated over the workload's
// containers that carry it. Only the (vulnerability, package) that can count
// somewhere are kept: KEV, critical, high, or covered by an exception on a
// workload. The order is deterministic.
func HistoryFacts(ds *model.Dataset, env string) []model.HistoryFact {
	type key struct {
		vuln, pkg, typ string
		wl             model.WorkloadRef
	}
	type group struct{ vuln, pkg, typ string }
	facts := map[key]*model.HistoryFact{}
	counts := map[group]bool{}
	for _, c := range ds.Containers {
		if c.Env != env {
			continue
		}
		for _, r := range ds.Findings[c.Digest] {
			k := key{r.VulnID, r.Pkg.Name, r.Pkg.Type, c.WorkloadRef}
			f, ok := facts[k]
			if !ok {
				v := ds.Vulns[r.VulnID]
				sev := v.Severity
				if sev == "" {
					sev = model.Unknown
				}
				f = &model.HistoryFact{
					Env: env, WorkloadRef: c.WorkloadRef, VulnID: r.VulnID, PkgName: r.Pkg.Name, PkgType: r.Pkg.Type,
					Severity: sev, KEV: v.KEV != nil && *v.KEV, Exposure: model.ExposureNone,
					Covered: slices.ContainsFunc(ds.Exceptions, func(e model.Exception) bool {
						return e.Covers(r.VulnID, r.Pkg.Name, model.AffectedContainer{WorkloadRef: c.WorkloadRef})
					}),
				}
				facts[k] = f
			}
			f.HasFix = f.HasFix || len(r.FixedIn) > 0
			f.Suspect = f.Suspect || Suspect(r.Pkg.Name, r.Pkg.Version, c.Image)
			f.Exposure = model.WiderExposure(f.Exposure, c.Exposure)
			g := group{r.VulnID, r.Pkg.Name, r.Pkg.Type}
			counts[g] = counts[g] || f.KEV || f.Severity == model.Critical || f.Severity == model.High || f.Covered
		}
	}
	out := make([]model.HistoryFact, 0, len(facts))
	for _, f := range facts {
		if counts[group{f.VulnID, f.PkgName, f.PkgType}] {
			out = append(out, *f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.VulnID != b.VulnID {
			return a.VulnID < b.VulnID
		}
		if a.PkgName != b.PkgName {
			return a.PkgName < b.PkgName
		}
		if a.PkgType != b.PkgType {
			return a.PkgType < b.PkgType
		}
		return a.WorkloadRef.Key() < b.WorkloadRef.Key()
	})
	return out
}

// InScope applies the filter of Scope to a fact: namespace, "namespace/name"
// and exposure in their lists (an empty list keeps all), combined with AND.
func InScope(f model.HistoryFact, namespaces, workloads, exposures []string) bool {
	return (len(namespaces) == 0 || slices.Contains(namespaces, f.Namespace)) &&
		(len(workloads) == 0 || slices.Contains(workloads, f.Namespace+"/"+f.Name)) &&
		(len(exposures) == 0 || slices.Contains(exposures, model.WiderExposure(model.ExposureNone, f.Exposure)))
}

// CountFacts counts the history numbers of facts exactly like Summary counts
// the findings of the same scope. Per (vulnerability, package): suspect on any
// workload, it is not counted at all; covered on every workload, it counts once
// as excepted; otherwise a fix on any workload and the widest exposure of the
// uncovered workloads decide. KEV, critical and high count distinct
// vulnerabilities. Any counting change in Summary goes here too
// (TestCountFactsMatchesSummary).
func CountFacts(facts []model.HistoryFact) (kev, criticalFixable, highFixableInternet, excepted int) {
	type key struct{ vuln, pkg, typ string }
	type group struct {
		sev                     model.Severity
		kev, fix, suspect, open bool
		exposure                string
	}
	groups := map[key]*group{}
	for _, f := range facts {
		k := key{f.VulnID, f.PkgName, f.PkgType}
		g := groups[k]
		if g == nil {
			g = &group{sev: f.Severity, exposure: model.ExposureNone}
			groups[k] = g
		}
		if f.Severity.Rank() > g.sev.Rank() {
			g.sev = f.Severity
		}
		g.kev = g.kev || f.KEV
		g.fix = g.fix || f.HasFix
		g.suspect = g.suspect || f.Suspect
		if !f.Covered {
			g.open = true
			g.exposure = model.WiderExposure(g.exposure, f.Exposure)
		}
	}
	kevs, crit, high := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for k, g := range groups {
		switch {
		case g.suspect:
			continue
		case !g.open:
			excepted++
			continue
		}
		if g.kev {
			kevs[k.vuln] = true
		}
		if g.sev == model.Critical && g.fix {
			crit[k.vuln] = true
		}
		if g.sev == model.High && g.fix && g.exposure == model.ExposureInternet {
			high[k.vuln] = true
		}
	}
	return len(kevs), len(crit), len(high), excepted
}
