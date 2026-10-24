// Package scan produces SBOMs and matches them against a vulnerability DB.
//
// The CLI implementation runs pinned syft and grype binaries shipped in the
// container image rather than importing them as libraries: their Go APIs move
// fast, their CLIs and JSON outputs are stable, and grype manages its own DB.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
)

type Result struct {
	Matches []model.Match
	DBBuilt time.Time
}

type Scanner interface {
	// SBOM generates an SBOM for a pullable image reference (repo@sha256:...).
	SBOM(ctx context.Context, ref string) ([]byte, error)
	// Match matches an SBOM against the current vulnerability DB.
	Match(ctx context.Context, sbom []byte) (Result, error)
	// UpdateDB refreshes the vulnerability DB and returns its build time.
	UpdateDB(ctx context.Context) (time.Time, error)
}

type CLI struct {
	Syft        string        // path to syft, default "syft"
	Grype       string        // path to grype, default "grype"
	SBOMTimeout time.Duration // pulling large images can be slow
}

func (c *CLI) SBOM(ctx context.Context, ref string) ([]byte, error) {
	timeout := c.SBOMTimeout
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// registry: pulls straight from the registry, no container daemon needed.
	// No -q: it also hides the error explaining a failed pull.
	syft := or(c.Syft, "syft")
	out, err := run(ctx, nil, syft, "scan", "registry:"+ref, "-o", "syft-json")
	// syft picks the variant of its own platform, and a cluster can mix amd64
	// and arm64 nodes: an image built for the other one only has a variant for it.
	var ce *cmdError
	if errors.As(err, &ce) && otherPlatform != "" && strings.Contains(ce.stderr, "no child with platform") {
		return run(ctx, nil, syft, "scan", "registry:"+ref, "--platform", otherPlatform, "-o", "syft-json")
	}
	return out, err
}

var otherPlatform = map[string]string{"amd64": "linux/arm64", "arm64": "linux/amd64"}[runtime.GOARCH]

func (c *CLI) Match(ctx context.Context, sbom []byte) (Result, error) {
	// Applied at match time so that stored SBOMs benefit on the next rematch.
	sbom, _, err := PruneShadowedBinaries(sbom)
	if err != nil {
		return Result{}, err
	}
	f, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(sbom); err != nil {
		f.Close()
		return Result{}, err
	}
	if err := f.Close(); err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	// The DB is only updated by UpdateDB so that every image of a rematch run
	// is matched against the same DB build.
	out, err := run(ctx, []string{"GRYPE_DB_AUTO_UPDATE=false"}, or(c.Grype, "grype"), "sbom:"+f.Name(), "-o", "json")
	if err != nil {
		return Result{}, err
	}
	return ParseGrype(out, Catalogers(sbom))
}

func (c *CLI) UpdateDB(ctx context.Context) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	grype := or(c.Grype, "grype")
	if _, err := run(ctx, nil, grype, "db", "update"); err != nil {
		return time.Time{}, err
	}
	out, err := run(ctx, nil, grype, "db", "status", "-o", "json")
	if err != nil {
		return time.Time{}, err
	}
	var status map[string]any
	if err := json.Unmarshal(out, &status); err != nil {
		return time.Time{}, fmt.Errorf("grype db status: %w", err)
	}
	if t, ok := findBuilt(status); ok {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("grype db status: no build time in %s", truncate(string(out), 200))
}

func run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, &cmdError{name, args[0], err, Redact(ansi.ReplaceAllString(strings.TrimSpace(stderr.String()), ""))}
	}
	return stdout.Bytes(), nil
}

type cmdError struct {
	name, arg string
	err       error
	stderr    string // redacted
}

// Error keeps the end of the output, where the cause is.
func (e *cmdError) Error() string {
	return fmt.Sprintf("%s %s: %v: %s", e.name, e.arg, e.err, tail(e.stderr, 600))
}

func (e *cmdError) Unwrap() error { return e.err }

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var (
	ansi     = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	urlQuery = regexp.MustCompile(`(https?://[^\s?"']+)\?[^\s"']*[^\s"':,.)]`)
)

// Redact drops URL query strings from scanner output before it is stored and
// shown: registry blob redirects are pre-signed URLs (X-Amz-Credential,
// X-Amz-Security-Token, X-Amz-Signature...).
func Redact(s string) string {
	return urlQuery.ReplaceAllString(s, "$1?…")
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
