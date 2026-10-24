package scan

import (
	"strings"
	"testing"

	"github.com/n0cl0ud/paindash/internal/model"
)

const grypeSample = `{
  "matches": [
    {
      "vulnerability": {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "dataSource": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
        "severity": "High",
        "description": "",
        "cvss": [],
        "fix": {"versions": ["2.17.1"], "state": "fixed"}
      },
      "relatedVulnerabilities": [
        {"id": "CVE-2021-44228", "description": "Log4Shell", "cvss": [{"metrics": {"baseScore": 10.0}}]}
      ],
      "artifact": {"id": "pkg-log4j", "name": "log4j-core", "version": "2.14.1", "type": "java-archive", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "locations": [{"path": "/app/lib/log4j-core-2.14.1.jar"}]}
    },
    {
      "vulnerability": {
        "id": "CVE-2023-0001",
        "severity": "medium",
        "urls": ["https://example.org/CVE-2023-0001"],
        "cvss": [{"metrics": {"baseScore": 5.3}}, {"metrics": {"baseScore": 6.1}}],
        "fix": {"versions": [], "state": "not-fixed"}
      },
      "artifact": {"name": "zlib", "version": "1.2.13", "type": "apk", "purl": ""}
    }
  ],
  "descriptor": {"db": {"status": {"built": "2026-10-21T04:12:00Z", "valid": true}}}
}`

func TestParseGrype(t *testing.T) {
	res, err := ParseGrype([]byte(grypeSample), map[string]string{"pkg-log4j": "java-archive-cataloger"})
	if err != nil {
		t.Fatal(err)
	}
	if res.DBBuilt.IsZero() || res.DBBuilt.Day() != 21 {
		t.Errorf("DBBuilt = %v", res.DBBuilt)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("got %d matches", len(res.Matches))
	}

	m := res.Matches[0]
	if m.Vuln.ID != "CVE-2021-44228" || len(m.Vuln.Aliases) != 1 || m.Vuln.Aliases[0] != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("GHSA not mapped to its CVE: id=%s aliases=%v", m.Vuln.ID, m.Vuln.Aliases)
	}
	if m.Vuln.Description != "Log4Shell" || m.Vuln.CVSS == nil || *m.Vuln.CVSS != 10 {
		t.Errorf("related data not used: %+v", m.Vuln)
	}
	if len(m.FixedIn) != 1 || m.FixedIn[0] != "2.17.1" {
		t.Errorf("FixedIn = %v", m.FixedIn)
	}

	m = res.Matches[1]
	if m.Vuln.Severity != model.Medium || *m.Vuln.CVSS != 6.1 || m.Vuln.URL != "https://example.org/CVE-2023-0001" {
		t.Errorf("unexpected vuln %+v", m.Vuln)
	}
	if m.FixedIn != nil {
		t.Errorf("not-fixed should have no FixedIn, got %v", m.FixedIn)
	}
	if m.Pkg.PURL != "pkg:generic/zlib@1.2.13" {
		t.Errorf("PURL fallback = %s", m.Pkg.PURL)
	}
	if res.Matches[0].Source != model.SourceManifest || res.Matches[0].Location != "/app/lib/log4j-core-2.14.1.jar" {
		t.Errorf("log4j source/location = %s %s", res.Matches[0].Source, res.Matches[0].Location)
	}
	if m.Source != model.SourceOS { // no cataloger known: from the apk type
		t.Errorf("zlib source = %s", m.Source)
	}
}

func TestRedact(t *testing.T) {
	in := `GET https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/abc/def?X-Amz-Algorithm=AWS4&X-Amz-Credential=ASIA123&X-Amz-Security-Token=tok&X-Amz-Signature=sig: 403 Forbidden`
	got := Redact(in)
	if strings.Contains(got, "ASIA123") || strings.Contains(got, "tok") || strings.Contains(got, "sig:") && strings.Contains(got, "Signature") {
		t.Fatalf("credentials not redacted: %s", got)
	}
	if got != `GET https://prod-us-east-1-starport-layer-bucket.s3.us-east-1.amazonaws.com/abc/def?…: 403 Forbidden` {
		t.Errorf("Redact = %s", got)
	}
}
