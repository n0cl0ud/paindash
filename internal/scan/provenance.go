package scan

import (
	"encoding/json"
	"strings"
)

// Provenance reads where an image was built from in the OCI labels recorded by
// its syft-json SBOM (source.metadata.labels): the source repo URL and commit.
func Provenance(sbom []byte) (source, revision string) {
	var doc struct {
		Source struct {
			Metadata struct {
				Labels map[string]string `json:"labels"`
			} `json:"metadata"`
		} `json:"source"`
	}
	if json.Unmarshal(sbom, &doc) != nil {
		return "", ""
	}
	l := doc.Source.Metadata.Labels
	return label(l["org.opencontainers.image.source"]), label(l["org.opencontainers.image.revision"])
}

// label bounds a label value: it comes from the image, not from us.
func label(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return ""
	}
	return s
}
