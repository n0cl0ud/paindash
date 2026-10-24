package scan

import (
	"encoding/json"
	"testing"
)

func TestPruneShadowedBinaries(t *testing.T) {
	sbom := `{
	  "artifacts": [
	    {"id": "a", "name": "github.com/traefik/traefik/v3", "version": "v3.4.1", "foundBy": "go-module-binary-cataloger", "locations": [{"path": "/traefik"}]},
	    {"id": "b", "name": "stdlib", "version": "go1.24.4", "foundBy": "go-module-binary-cataloger", "locations": [{"path": "/traefik"}]},
	    {"id": "c", "name": "traefik", "version": "1.24.4", "foundBy": "binary-classifier-cataloger", "locations": [{"path": "/traefik"}]},
	    {"id": "d", "name": "nginx", "version": "1.27.0", "foundBy": "binary-classifier-cataloger", "locations": [{"path": "/usr/sbin/nginx"}]}
	  ],
	  "artifactRelationships": [
	    {"parent": "c", "child": "x", "type": "contains"},
	    {"parent": "a", "child": "b", "type": "dependency-of"}
	  ],
	  "source": {"id": "s"}
	}`
	out, n, err := PruneShadowedBinaries([]byte(sbom))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("dropped %d packages, want 1", n)
	}
	var doc struct {
		Artifacts []struct {
			ID string `json:"id"`
		} `json:"artifacts"`
		Relationships []struct {
			Parent string `json:"parent"`
		} `json:"artifactRelationships"`
		Source map[string]string `json:"source"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var ids string
	for _, a := range doc.Artifacts {
		ids += a.ID
	}
	// The Go binary keeps its build-info packages; nginx (not a Go binary)
	// keeps its classifier package.
	if ids != "abd" || len(doc.Relationships) != 1 || doc.Source["id"] != "s" {
		t.Errorf("ids=%s relationships=%d source=%v", ids, len(doc.Relationships), doc.Source)
	}

	same, n, err := PruneShadowedBinaries([]byte(`{"artifacts": []}`))
	if err != nil || n != 0 || string(same) != `{"artifacts": []}` {
		t.Errorf("no-op case: n=%d err=%v out=%s", n, err, same)
	}
}
