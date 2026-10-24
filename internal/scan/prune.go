package scan

import (
	"encoding/json"
	"fmt"
)

// RulesVersion changes whenever the SBOM pruning or matching rules change, so
// that the stored SBOMs get rematched once with the new rules.
const RulesVersion = "2"

// Catalogers maps the package IDs of a syft JSON SBOM to the cataloger that
// found each package.
func Catalogers(sbom []byte) map[string]string {
	var doc struct {
		Artifacts []struct {
			ID      string `json:"id"`
			FoundBy string `json:"foundBy"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(sbom, &doc) != nil {
		return nil
	}
	out := make(map[string]string, len(doc.Artifacts))
	for _, a := range doc.Artifacts {
		out[a.ID] = a.FoundBy
	}
	return out
}

// Catalogers that identify a binary from build metadata embedded by its
// toolchain: exact module versions, unlike the binary classifier.
var buildInfoCatalogers = map[string]bool{
	"go-module-binary-cataloger":       true,
	"cargo-auditable-binary-cataloger": true,
}

// PruneShadowedBinaries drops the packages the binary classifier guessed for
// files that a build-info cataloger already identified. The classifier
// pattern-matches version strings and can pick the wrong one, such as
// "traefik 1.24.4" (the Go toolchain version) for a traefik v3 binary, which
// then matches dozens of traefik 1.x CVEs. It returns the SBOM and the count
// of dropped packages.
func PruneShadowedBinaries(sbom []byte) ([]byte, int, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(sbom, &doc); err != nil {
		return nil, 0, fmt.Errorf("parse sbom: %w", err)
	}
	var artifacts []map[string]json.RawMessage
	if err := json.Unmarshal(doc["artifacts"], &artifacts); err != nil {
		return sbom, 0, nil // not a syft JSON document: leave it alone
	}

	type pkg struct {
		ID        string `json:"id"`
		FoundBy   string `json:"foundBy"`
		Locations []struct {
			Path string `json:"path"`
		} `json:"locations"`
	}
	parsed := make([]pkg, len(artifacts))
	identified := map[string]bool{}
	for i, a := range artifacts {
		raw, _ := json.Marshal(a)
		if err := json.Unmarshal(raw, &parsed[i]); err != nil {
			return nil, 0, err
		}
		if buildInfoCatalogers[parsed[i].FoundBy] {
			for _, l := range parsed[i].Locations {
				identified[l.Path] = true
			}
		}
	}

	dropped := map[string]bool{}
	kept := artifacts[:0]
	for i, a := range artifacts {
		p := parsed[i]
		shadowed := p.FoundBy == "binary-classifier-cataloger" && len(p.Locations) > 0
		for _, l := range p.Locations {
			shadowed = shadowed && identified[l.Path]
		}
		if shadowed {
			dropped[p.ID] = true
			continue
		}
		kept = append(kept, a)
	}
	if len(dropped) == 0 {
		return sbom, 0, nil
	}
	if doc["artifacts"], _ = json.Marshal(kept); doc["artifactRelationships"] != nil {
		var rels []struct {
			Parent string `json:"parent"`
			Child  string `json:"child"`
		}
		var raw []json.RawMessage
		if json.Unmarshal(doc["artifactRelationships"], &raw) == nil && json.Unmarshal(doc["artifactRelationships"], &rels) == nil {
			keep := raw[:0]
			for i, r := range rels {
				if !dropped[r.Parent] && !dropped[r.Child] {
					keep = append(keep, raw[i])
				}
			}
			doc["artifactRelationships"], _ = json.Marshal(keep)
		}
	}
	out, err := json.Marshal(doc)
	return out, len(dropped), err
}
