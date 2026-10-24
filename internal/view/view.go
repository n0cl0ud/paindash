// Package view derives the API read models (findings, summary, workloads) of
// one environment from a store Dataset.
package view

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

// Scope restricts a dataset to some namespaces and/or workloads ("ns/name").
// The filter is env-independent, so promotion hints still compare the same
// workloads across envs. Empty lists mean no restriction.
func Scope(ds *model.Dataset, namespaces, workloads, exposures []string) *model.Dataset {
	if len(namespaces) == 0 && len(workloads) == 0 && len(exposures) == 0 {
		return ds
	}
	scoped := *ds
	scoped.Containers = nil
	scoped.Unscoped = ds
	for _, c := range ds.Containers {
		if len(namespaces) > 0 && !slices.Contains(namespaces, c.Namespace) {
			continue
		}
		if len(workloads) > 0 && !slices.Contains(workloads, c.Namespace+"/"+c.Name) {
			continue
		}
		if len(exposures) > 0 && !slices.Contains(exposures, model.WiderExposure(model.ExposureNone, c.Exposure)) {
			continue
		}
		scoped.Containers = append(scoped.Containers, c)
	}
	return &scoped
}

// Findings groups the findings of the containers running in env by
// (vuln, package name), most urgent first. Different versions of the same
// package are one row to fix, so they are merged ("1.4.0, 1.5.0").
func Findings(ds *model.Dataset, env string) []model.Finding {
	type key struct{ vuln, pkg, typ string }
	groups := map[key]*model.Finding{}
	affected := map[key]map[string]bool{} // dedupe containers
	versions := map[key][]string{}
	fixes := map[key][]string{}
	var order []key

	for _, c := range ds.Containers {
		if c.Env != env {
			continue
		}
		for _, f := range ds.Findings[c.Digest] {
			k := key{f.VulnID, f.Pkg.Name, f.Pkg.Type}
			g, ok := groups[k]
			if !ok {
				g = newFinding(ds.Vulns[f.VulnID], f)
				groups[k], affected[k] = g, map[string]bool{}
				order = append(order, k)
			}
			versions[k] = appendUnique(versions[k], f.Pkg.Version)
			fixes[k] = appendUnique(fixes[k], f.FixedIn...)
			if seen := affected[k]; !seen[c.Key()] {
				seen[c.Key()] = true
				g.Workloads = append(g.Workloads, model.AffectedContainer{
					WorkloadRef: c.WorkloadRef, Exposure: model.WiderExposure(model.ExposureNone, c.Exposure),
					Container: c.Container, Image: c.Image, Digest: c.Digest,
				})
			}
			first := f.FirstSeen
			if c.FirstSeen.After(first) {
				first = c.FirstSeen
			}
			if first.Before(g.FirstSeen) {
				g.FirstSeen = first
			}
		}
	}

	hasVuln := vulnIndex(ds)
	promo := promotionIndex(ds)
	out := make([]model.Finding, 0, len(order))
	for _, k := range order {
		g := groups[k]
		sort.Strings(versions[k])
		g.Package.Version = strings.Join(versions[k], ", ")
		if fixes[k] != nil {
			sort.Strings(fixes[k])
			g.FixedIn = fixes[k]
		}
		g.Suspect = slices.ContainsFunc(g.Workloads, func(w model.AffectedContainer) bool {
			return Suspect(g.Package.Name, versions[k][0], w.Image)
		})
		applyExceptions(g, ds.Exceptions)
		g.Exposure = model.ExposureNone
		for _, w := range g.Workloads {
			g.Exposure = model.WiderExposure(g.Exposure, w.Exposure)
		}
		g.Promotion = promotionHints(env, g, promo, hasVuln)
		sort.Slice(g.Workloads, func(i, j int) bool {
			return g.Workloads[i].WorkloadRef.Key()+g.Workloads[i].Container < g.Workloads[j].WorkloadRef.Key()+g.Workloads[j].Container
		})
		out = append(out, *g)
	}
	SortByUrgency(out)
	return out
}

func newFinding(v model.Vuln, f model.FindingRow) *model.Finding {
	sev := v.Severity
	if sev == "" {
		sev = model.Unknown
	}
	fixed := f.FixedIn
	if fixed == nil {
		fixed = []string{}
	}
	aliases := v.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	return &model.Finding{
		VulnID:         f.VulnID,
		Aliases:        aliases,
		Severity:       sev,
		CVSS:           v.CVSS,
		EPSS:           v.EPSS,
		EPSSPercentile: v.EPSSPercentile,
		KEV:            v.KEV != nil && *v.KEV,
		KEVAddedAt:     v.KEVAddedAt,
		Description:    v.Description,
		URL:            v.URL,
		Package:        f.Pkg,
		FixedIn:        fixed,
		FirstSeen:      time.Now().Add(24 * 365 * 100 * time.Hour), // lowered while grouping
		Workloads:      []model.AffectedContainer{},
		Promotion:      []model.PromotionHint{},
		Source:         cmpOr(f.Source, model.SourceUnknown),
		Location:       f.Location,
	}
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// applyExceptions drops the workloads covered by an active exception. When
// they all are, the finding keeps them and carries the exception instead.
func applyExceptions(f *model.Finding, exceptions []model.Exception) {
	var open []model.AffectedContainer
	var by *model.Exception
	for _, w := range f.Workloads {
		i := slices.IndexFunc(exceptions, func(e model.Exception) bool { return e.Covers(f.VulnID, f.Package.Name, w) })
		if i < 0 {
			open = append(open, w)
		} else if by == nil {
			by = &exceptions[i]
		}
	}
	switch {
	case by == nil:
	case len(open) == 0:
		e := *by
		f.Exception = &e
	default:
		f.Workloads = open
	}
}

var (
	majorRe    = regexp.MustCompile(`^\d+`)
	modMajorRe = regexp.MustCompile(`^v\d+$`)
)

// Suspect reports a package named like the image it was found in (e.g.
// "traefik" in .../traefik:v3.4.1) whose major version differs from the image
// tag's: the scanner most likely misidentified it.
func Suspect(pkgName, version, image string) bool {
	repo := image
	if i := strings.Index(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	slash := strings.LastIndex(repo, "/")
	colon := strings.LastIndex(repo, ":")
	if colon <= slash {
		return false // no tag to compare with
	}
	tag, repo := repo[colon+1:], repo[slash+1:colon]

	parts := strings.Split(pkgName, "/")
	name := parts[len(parts)-1]
	if len(parts) > 1 && modMajorRe.MatchString(name) { // Go module major suffix: .../traefik/v3
		name = parts[len(parts)-2]
	}
	if !strings.EqualFold(name, repo) {
		return false
	}
	tagMajor, ok1 := major(tag)
	pkgMajor, ok2 := major(version)
	return ok1 && ok2 && tagMajor != pkgMajor
}

func major(v string) (string, bool) {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "go"), "v")
	m := majorRe.FindString(v)
	return strings.TrimLeft(m, "0"), m != ""
}

func appendUnique(list []string, vals ...string) []string {
	for _, v := range vals {
		if v != "" && !slices.Contains(list, v) {
			list = append(list, v)
		}
	}
	return list
}

// vulnIndex returns digest -> set of vuln IDs.
func vulnIndex(ds *model.Dataset) map[string]map[string]bool {
	idx := make(map[string]map[string]bool, len(ds.Findings))
	for d, rows := range ds.Findings {
		set := make(map[string]bool, len(rows))
		for _, r := range rows {
			set[r.VulnID] = true
		}
		idx[d] = set
	}
	return idx
}

// promotionIndex groups the scanned containers of every env by workload
// container (namespace/kind/name/container), the candidates of promotion hints.
func promotionIndex(ds *model.Dataset) map[string][]model.Container {
	root := ds
	if ds.Unscoped != nil {
		root = ds.Unscoped
	}
	idx := map[string][]model.Container{}
	for _, c := range root.Containers {
		if root.ImageStatus[c.Digest] == "scanned" {
			idx[c.PromotionKey()] = append(idx[c.PromotionKey()], c)
		}
	}
	return idx
}

// promotionHints lists other envs where the same workload container runs a
// scanned image that does not have this vuln: the fix exists, ship it.
func promotionHints(env string, f *model.Finding, idx map[string][]model.Container, hasVuln map[string]map[string]bool) []model.PromotionHint {
	seen := map[string]bool{}
	hints := []model.PromotionHint{}
	for _, a := range f.Workloads {
		for _, c := range idx[a.Namespace+"/"+a.Kind+"/"+a.Name+"/"+a.Container] {
			if c.Env == env || hasVuln[c.Digest][f.VulnID] {
				continue
			}
			if k := c.Env + c.Digest; !seen[k] {
				seen[k] = true
				hints = append(hints, model.PromotionHint{Env: c.Env, Cluster: c.Cluster, Image: c.Image, Digest: c.Digest})
			}
		}
	}
	sort.Slice(hints, func(i, j int) bool { return hints[i].Env+hints[i].Image < hints[j].Env+hints[j].Image })
	return hints
}

// KeepPromotions drops the promotion hints that would not move a fix forward
// along chain (e.g. dev, test, prod): an image from a later env is a rollback,
// one from an env outside the chain is unrelated. An empty chain keeps all.
func KeepPromotions(fs []model.Finding, env string, chain []string) {
	at := slices.Index(chain, env)
	if len(chain) == 0 {
		return
	}
	for i := range fs {
		kept := []model.PromotionHint{}
		for _, h := range fs[i].Promotion {
			if j := slices.Index(chain, h.Env); at >= 0 && j >= 0 && j < at {
				kept = append(kept, h)
			}
		}
		fs[i].Promotion = kept
	}
}

// SortByUrgency orders findings: KEV, then severity, then exposure (internet
// first), then EPSS, then fixable.
func SortByUrgency(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.KEV != b.KEV {
			return a.KEV
		}
		if ra, rb := a.Severity.Rank(), b.Severity.Rank(); ra != rb {
			return ra > rb
		}
		if ea, eb := model.ExposureRank(a.Exposure), model.ExposureRank(b.Exposure); ea != eb {
			return ea > eb
		}
		if ea, eb := epss(a), epss(b); ea != eb {
			return ea > eb
		}
		if fa, fb := len(a.FixedIn) > 0, len(b.FixedIn) > 0; fa != fb {
			return fa
		}
		return a.VulnID < b.VulnID
	})
}

func epss(f model.Finding) float64 {
	if f.EPSS == nil {
		return -1
	}
	return *f.EPSS
}

type Filter struct {
	Severities      []model.Severity // empty: all
	KEV             bool
	Fixable         bool
	Query           string
	IncludeSuspect  bool // suspect and fully excepted findings are left out unless asked for
	IncludeExcepted bool
}

func (flt Filter) Match(f model.Finding) bool {
	if (f.Suspect && !flt.IncludeSuspect) || (f.Exception != nil && !flt.IncludeExcepted) {
		return false
	}
	if flt.KEV && !f.KEV {
		return false
	}
	if flt.Fixable && len(f.FixedIn) == 0 {
		return false
	}
	if len(flt.Severities) > 0 {
		ok := false
		for _, s := range flt.Severities {
			ok = ok || s == f.Severity
		}
		if !ok {
			return false
		}
	}
	if q := strings.ToLower(strings.TrimSpace(flt.Query)); q != "" {
		hay := []string{f.VulnID, f.Package.Name, f.Package.PURL}
		hay = append(hay, f.Aliases...)
		for _, w := range f.Workloads {
			hay = append(hay, w.Namespace+"/"+w.Name, w.Image)
		}
		found := false
		for _, h := range hay {
			if strings.Contains(strings.ToLower(h), q) {
				found = true
				break
			}
		}
		return found
	}
	return true
}

func Summary(ds *model.Dataset, env string, findings []model.Finding) model.Summary {
	s := model.Summary{Env: env, BySeverity: model.SeverityCounts()}
	kev, critFix, highFixNet := map[string]bool{}, map[string]bool{}, map[string]bool{}
	affected, internet := map[string]bool{}, map[string]bool{}
	for _, f := range findings {
		if f.Suspect {
			s.Suspect++
			continue
		}
		if f.Exception != nil {
			s.Excepted++
			continue
		}
		s.BySeverity[f.Severity]++
		if f.KEV {
			kev[f.VulnID] = true
		}
		if f.Severity == model.Critical && len(f.FixedIn) > 0 {
			critFix[f.VulnID] = true
		}
		if f.Severity == model.High && len(f.FixedIn) > 0 && f.Exposure == model.ExposureInternet {
			highFixNet[f.VulnID] = true
		}
		if f.Severity.Rank() >= model.High.Rank() {
			for _, w := range f.Workloads {
				affected[w.WorkloadRef.Key()] = true
				if w.Exposure == model.ExposureInternet {
					internet[w.WorkloadRef.Key()] = true
				}
			}
		}
	}
	s.KEV, s.CriticalFixable, s.WorkloadsAffected, s.InternetAffected = len(kev), len(critFix), len(affected), len(internet)
	s.HighFixableInternet = len(highFixNet)

	all, digests := map[string]bool{}, map[string]bool{}
	for _, c := range ds.Containers {
		if c.Env == env {
			all[c.WorkloadRef.Key()] = true
			digests[c.Digest] = true
		}
	}
	s.WorkloadsTotal = len(all)
	now := time.Now()
	for _, e := range ds.Exceptions {
		if e.StateAt(now) == "expiring" {
			s.ExceptionsExpiring++
		}
	}
	for d := range digests {
		s.Images.Total++
		switch ds.ImageStatus[d] {
		case "scanned":
			s.Images.Scanned++
		case "failed":
			s.Images.Failed++
		default:
			s.Images.Pending++
		}
	}
	return s
}

// Images lists the images running in env whose scan status is one of
// statuses, with the workloads running them; failed ones first.
func Images(ds *model.Dataset, env string, statuses []string) []model.ImageScan {
	byDigest := map[string]*model.ImageScan{}
	var order []string
	for _, c := range ds.Containers {
		st := ds.ImageStatus[c.Digest]
		if c.Env != env || !slices.Contains(statuses, st) {
			continue
		}
		img, ok := byDigest[c.Digest]
		if !ok {
			e := ds.ImageErrors[c.Digest]
			img = &model.ImageScan{Image: c.Image, Digest: c.Digest, Status: st, Error: e.Error, Attempts: e.Attempts, Workloads: []model.AffectedContainer{}}
			byDigest[c.Digest] = img
			order = append(order, c.Digest)
		}
		img.Workloads = append(img.Workloads, model.AffectedContainer{WorkloadRef: c.WorkloadRef, Container: c.Container, Image: c.Image, Digest: c.Digest})
	}
	out := make([]model.ImageScan, 0, len(order))
	for _, d := range order {
		out = append(out, *byDigest[d])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Status == "failed") != (out[j].Status == "failed") {
			return out[i].Status == "failed"
		}
		return out[i].Image < out[j].Image
	})
	return out
}

// Workloads lists the workloads of env with their vulnerability counts. The
// counts come from Findings, so suspect and excepted findings are left out,
// like everywhere else.
func Workloads(ds *model.Dataset, env string) []model.Workload {
	return WorkloadsFrom(ds, env, Findings(ds, env))
}

// WorkloadsFrom is Workloads with the findings of env already computed.
func WorkloadsFrom(ds *model.Dataset, env string, findings []model.Finding) []model.Workload {
	byKey := map[string]*model.Workload{}
	for _, c := range ds.Containers {
		if c.Env != env {
			continue
		}
		k := c.WorkloadRef.Key()
		w, ok := byKey[k]
		if !ok {
			w = &model.Workload{WorkloadRef: c.WorkloadRef, Env: env, Exposure: model.ExposureNone, Counts: model.SeverityCounts(), Containers: []model.WorkloadContainer{}}
			byKey[k] = w
		}
		w.Exposure = model.WiderExposure(w.Exposure, c.Exposure)
		w.Containers = append(w.Containers, model.WorkloadContainer{Name: c.Container, Image: c.Image, Digest: c.Digest})
		if c.FirstSeen.After(w.LastChangeAt) {
			w.LastChangeAt = c.FirstSeen
		}
	}
	type vulnInfo struct {
		sev          model.Severity
		kev, fixable bool
	}
	vulns := map[string]map[string]vulnInfo{} // workload -> vuln id
	for _, f := range findings {
		if f.Suspect || f.Exception != nil {
			continue
		}
		for _, a := range f.Workloads {
			k := a.WorkloadRef.Key()
			if vulns[k] == nil {
				vulns[k] = map[string]vulnInfo{}
			}
			v := vulns[k][f.VulnID]
			if f.Severity.Rank() > v.sev.Rank() {
				v.sev = f.Severity
			}
			v.kev = v.kev || f.KEV
			v.fixable = v.fixable || len(f.FixedIn) > 0
			vulns[k][f.VulnID] = v
		}
	}
	out := make([]model.Workload, 0, len(byKey))
	for k, w := range byKey {
		for _, v := range vulns[k] {
			sev := v.sev
			if sev == "" {
				sev = model.Unknown
			}
			w.Counts[sev]++
			if v.kev {
				w.KEV++
			}
			if v.fixable {
				w.Fixable++
			}
		}
		sort.Slice(w.Containers, func(i, j int) bool { return w.Containers[i].Name < w.Containers[j].Name })
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.KEV != b.KEV {
			return a.KEV > b.KEV
		}
		if a.Counts[model.Critical] != b.Counts[model.Critical] {
			return a.Counts[model.Critical] > b.Counts[model.Critical]
		}
		if a.Counts[model.High] != b.Counts[model.High] {
			return a.Counts[model.High] > b.Counts[model.High]
		}
		return a.WorkloadRef.Key() < b.WorkloadRef.Key()
	})
	return out
}
