package scan

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

// Subset of grype's JSON output (-o json) that paindash uses.
type grypeOutput struct {
	Matches []struct {
		Vulnerability          grypeVuln   `json:"vulnerability"`
		RelatedVulnerabilities []grypeVuln `json:"relatedVulnerabilities"`
		Artifact               struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			PURL      string `json:"purl"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
	Descriptor struct {
		DB map[string]any `json:"db"`
	} `json:"descriptor"`
}

type grypeVuln struct {
	ID          string   `json:"id"`
	DataSource  string   `json:"dataSource"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	URLs        []string `json:"urls"`
	CVSS        []struct {
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
	Fix struct {
		Versions []string `json:"versions"`
		State    string   `json:"state"`
	} `json:"fix"`
}

// ParseGrype converts grype JSON into matches. Advisories such as GHSA-... are
// reported under their CVE alias when there is one, so EPSS and KEV (keyed by
// CVE) apply and the same flaw is not counted twice across ecosystems.
// foundBy maps SBOM package IDs to the syft cataloger that found them (nil
// when unknown); it gives each match its identification source.
func ParseGrype(data []byte, foundBy map[string]string) (Result, error) {
	var out grypeOutput
	if err := json.Unmarshal(data, &out); err != nil {
		return Result{}, fmt.Errorf("parse grype output: %w", err)
	}
	var res Result
	if t, ok := findBuilt(out.Descriptor.DB); ok {
		res.DBBuilt = t
	}
	for _, m := range out.Matches {
		v := m.Vulnerability
		id := v.ID
		aliases := []string{}
		for _, r := range m.RelatedVulnerabilities {
			if r.ID != "" && r.ID != v.ID {
				aliases = append(aliases, r.ID)
			}
		}
		if !strings.HasPrefix(id, "CVE-") {
			for i, a := range aliases {
				if strings.HasPrefix(a, "CVE-") {
					aliases[i], id = id, a
					break
				}
			}
		}
		sort.Strings(aliases)

		description := v.Description
		cvss := maxScore(v)
		for _, r := range m.RelatedVulnerabilities {
			if description == "" {
				description = r.Description
			}
			if s := maxScore(r); s != nil && (cvss == nil || *s > *cvss) {
				cvss = s
			}
		}
		url := v.DataSource
		if url == "" && len(v.URLs) > 0 {
			url = v.URLs[0]
		}
		var fixed []string
		if v.Fix.State == "fixed" {
			fixed = v.Fix.Versions
		}
		location := ""
		if len(m.Artifact.Locations) > 0 {
			location = m.Artifact.Locations[0].Path
		}
		purl := m.Artifact.PURL
		if purl == "" {
			purl = "pkg:generic/" + m.Artifact.Name + "@" + m.Artifact.Version
		}
		res.Matches = append(res.Matches, model.Match{
			Vuln: model.Vuln{
				ID:          id,
				Aliases:     aliases,
				Severity:    model.ParseSeverity(v.Severity),
				CVSS:        cvss,
				Description: description,
				URL:         url,
			},
			Pkg:      model.Package{Name: m.Artifact.Name, Version: m.Artifact.Version, Type: m.Artifact.Type, PURL: purl},
			FixedIn:  fixed,
			Source:   SourceOf(foundBy[m.Artifact.ID], m.Artifact.Type),
			Location: location,
		})
	}
	return res, nil
}

// SourceOf classifies how a package was identified, from the syft cataloger
// that found it, or from its package type when the cataloger is unknown.
func SourceOf(foundBy, pkgType string) string {
	switch {
	case buildInfoCatalogers[foundBy] || foundBy == "elf-binary-package-cataloger":
		return model.SourceBuildInfo
	case foundBy == "binary-classifier-cataloger":
		return model.SourceHeuristic
	case strings.HasSuffix(foundBy, "-db-cataloger"): // apk-db, dpkg-db, rpm-db...
		return model.SourceOS
	case foundBy != "":
		return model.SourceManifest
	}
	switch pkgType {
	case "apk", "deb", "rpm", "alpm", "portage":
		return model.SourceOS
	case "binary":
		return model.SourceHeuristic
	case "":
		return model.SourceUnknown
	}
	return model.SourceManifest
}

func maxScore(v grypeVuln) *float64 {
	var best *float64
	for _, c := range v.CVSS {
		s := c.Metrics.BaseScore
		if s > 0 && (best == nil || s > *best) {
			best = &s
		}
	}
	return best
}

// findBuilt looks for the DB build time in grype's JSON. Its location moved
// across DB schema versions (db.built, db.status.built, ...), so search for it.
func findBuilt(m map[string]any) (time.Time, bool) {
	for k, v := range m {
		switch val := v.(type) {
		case string:
			if strings.EqualFold(k, "built") {
				if t, err := time.Parse(time.RFC3339, val); err == nil {
					return t, true
				}
			}
		case map[string]any:
			if t, ok := findBuilt(val); ok {
				return t, true
			}
		}
	}
	return time.Time{}, false
}
