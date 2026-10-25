package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSBOMOtherPlatform(t *testing.T) {
	if otherPlatform == "" {
		t.Skip("no other platform for this architecture")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the fake syft is a shell script")
	}
	// A fake syft for an image that only has a variant for the other platform.
	syft := filepath.Join(t.TempDir(), "syft")
	script := `#!/bin/sh
case "$*" in
*--platform*) echo "{\"args\":\"$*\"}" ;;
*) echo "  - oci-registry: failed to get image from registry: no child with platform linux/x in index r@sha256:1" >&2
   echo "  - oci-model: unexpected status code 401 Unauthorized" >&2
   exit 1 ;;
esac
`
	if err := os.WriteFile(syft, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := (&CLI{Syft: syft}).SBOM(context.Background(), "r@sha256:1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "--platform "+otherPlatform) {
		t.Fatalf("not retried on %s: %s", otherPlatform, out)
	}
}

func TestProvenance(t *testing.T) {
	sbom := `{"artifacts":[],"source":{"type":"image","metadata":{"userInput":"r@sha256:1","labels":{
		"org.opencontainers.image.source":" https://github.com/n0cl0ud/paindash ",
		"org.opencontainers.image.revision":"7f0c8394","org.opencontainers.image.title":"paindash"}}}}`
	if src, rev := Provenance([]byte(sbom)); src != "https://github.com/n0cl0ud/paindash" || rev != "7f0c8394" {
		t.Errorf("got %q %q", src, rev)
	}
	for _, sbom := range []string{`{"source":{"metadata":{}}}`, `{"source":{"type":"directory"}}`, `not json`} {
		if src, rev := Provenance([]byte(sbom)); src != "" || rev != "" {
			t.Errorf("%s: got %q %q", sbom, src, rev)
		}
	}
}
