// Package demo simulates clusters and a scanner so the whole pipeline (and
// the live UI) can run on a laptop: workloads get deployed in dev, promoted to
// test then prod, and the fake vulnerability DB publishes new CVEs over time.
// Vulnerability IDs use the year 2099 so they cannot be mistaken for real ones.
package demo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/n0cl0ud/paindash/internal/model"
	"github.com/n0cl0ud/paindash/internal/scan"
)

const registry = "registry.demo.local/"

var clusters = map[string]string{
	"prod": "prod-1",
	"test": "test-1",
	"dev":  "dev-1",
	"ops":  "ops-1",
}

var (
	appEnvs = []string{"prod", "test", "dev"}
	allEnvs = []string{"prod", "test", "dev", "ops"}
)

type workload struct {
	ns, kind, name string
	envs           []string
	pkgs           []string
	image          string // repository under the registry: ours are under acme/
	source         string // OCI source label, "" if the image has none
}

var workloads = []workload{
	{"checkout", "Deployment", "checkout-api", appEnvs, []string{"openssl", "glibc", "netty-codec-http", "jackson-databind", "spring-web"}, "acme/checkout-api", "https://github.com/acme/checkout"},
	{"checkout", "Deployment", "checkout-worker", appEnvs, []string{"openssl", "glibc", "jackson-databind", "postgresql-jdbc"}, "acme/checkout-worker", "https://github.com/acme/checkout"},
	{"catalog", "StatefulSet", "catalog", appEnvs, []string{"glibc", "openssl", "golang.org/x/net", "golang.org/x/crypto"}, "acme/catalog", "https://github.com/acme/catalog"},
	{"edge", "Deployment", "edge-api", appEnvs, []string{"openssl", "zlib", "golang.org/x/net", "google.golang.org/grpc"}, "acme/edge-api", ""},
	{"storefront", "Deployment", "storefront", appEnvs, []string{"busybox", "zlib", "express", "lodash"}, "acme/storefront", "https://github.com/acme/www.acme.example"},
	{"search", "StatefulSet", "opensearch", appEnvs, []string{"glibc", "netty-codec-http", "log4j-core", "grpc-netty"}, "opensearchproject/opensearch", ""},
	{"search", "Deployment", "data-prepper", appEnvs, []string{"glibc", "netty-codec-http", "jackson-databind"}, "opensearchproject/data-prepper", ""},
	{"analytics", "CronJob", "nightly-export", appEnvs, []string{"urllib3", "requests", "openssl"}, "acme/nightly-export", "https://github.com/acme/analytics"},
	{"ingress", "Deployment", "traefik", allEnvs, []string{"golang.org/x/net", "golang.org/x/crypto"}, "traefik/traefik", "https://github.com/traefik/traefik"},
	{"kube-system", "Deployment", "metrics-server", allEnvs, []string{"golang.org/x/net"}, "kubernetes-sigs/metrics-server", "https://github.com/kubernetes-sigs/metrics-server"},
	{"kube-system", "DaemonSet", "kube-proxy", allEnvs, []string{"glibc", "golang.org/x/net", "golang.org/x/crypto"}, "kubernetes/kube-proxy", "https://github.com/kubernetes/kubernetes"},
	{"monitoring", "StatefulSet", "prometheus", []string{"ops"}, []string{"golang.org/x/net", "busybox"}, "prometheus/prometheus", "https://github.com/prometheus/prometheus"},
	{"monitoring", "Deployment", "grafana", []string{"ops"}, []string{"openssl", "busybox", "golang.org/x/crypto"}, "grafana/grafana", "https://github.com/grafana/grafana"},
	{"minio", "StatefulSet", "minio", []string{"ops"}, []string{"golang.org/x/crypto", "busybox"}, "minio/minio", ""},
	{"pomerium", "Deployment", "pomerium", []string{"ops"}, []string{"golang.org/x/net", "envoy"}, "pomerium/pomerium", "https://github.com/pomerium/pomerium"},
}

func pkgType(name string) string {
	switch {
	case strings.Contains(name, "."):
		return "go-module"
	case name == "urllib3" || name == "requests":
		return "python"
	case name == "express" || name == "lodash":
		return "npm"
	case strings.Contains(name, "-") && name != "envoy":
		return "java-archive"
	}
	return "deb"
}

func purl(name, version string) string {
	switch pkgType(name) {
	case "go-module":
		return "pkg:golang/" + name + "@v" + version
	case "python":
		return "pkg:pypi/" + name + "@" + version
	case "npm":
		return "pkg:npm/" + name + "@" + version
	case "java-archive":
		return "pkg:maven/demo/" + name + "@" + version
	}
	return "pkg:deb/debian/" + name + "@" + version
}

func hash(s string) uint64 {
	h := sha256.Sum256([]byte(s))
	var n uint64
	for _, b := range h[:8] {
		n = n<<8 | uint64(b)
	}
	return n
}

func digestOf(name string, version int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("paindash-demo/%s/%d", name, version)))
	return "sha256:" + hex.EncodeToString(h[:])
}

// pkgVersion: each release upgrades the packages, so a release promoted from
// test often fixes what prod still runs.
func pkgVersion(wl workload, pkg string, release int) int {
	return int(hash(wl.name+pkg)%4) + release
}

// ---- inventory --------------------------------------------------------------

// Source simulates the four clusters.
type Source struct {
	Every time.Duration // how often something changes

	mu       sync.Mutex
	rng      *rand.Rand
	versions map[string]int // env/workload -> release
	last     time.Time
}

func NewSource(every time.Duration) *Source {
	s := &Source{Every: every, rng: rand.New(rand.NewPCG(42, 7)), versions: map[string]int{}, last: time.Now()}
	for _, wl := range workloads {
		if len(wl.envs) == 1 {
			s.versions["ops/"+wl.name] = 4
			continue
		}
		dev := 6 + s.rng.IntN(2)
		test := max(dev-1-s.rng.IntN(2), 1)
		prod := max(test-1-s.rng.IntN(2), 1)
		for env, v := range map[string]int{"dev": dev, "test": test, "prod": prod, "ops": prod} {
			s.versions[env+"/"+wl.name] = v
		}
	}
	return s
}

func (s *Source) Name() string { return "demo" }

// ExposureAvailable: the demo always knows how its workloads are exposed.
func (s *Source) ExposureAvailable() bool { return true }

var demoExposure = map[string]string{
	"edge-api":     model.ExposureInternet,
	"storefront":   model.ExposureInternet,
	"traefik":      model.ExposureInternet,
	"checkout-api": model.ExposureInternal,
	"pomerium":     model.ExposureInternal,
}

func (s *Source) Snapshot(ctx context.Context) ([]model.Container, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.last) >= s.Every {
		s.last = time.Now()
		s.step()
	}
	var out []model.Container
	for _, wl := range workloads {
		for _, env := range wl.envs {
			v := s.versions[env+"/"+wl.name]
			d := digestOf(wl.name, v)
			c := model.Container{
				Env:       env,
				Container: wl.name,
				Image:     fmt.Sprintf("%s%s:1.%d.0", registry, wl.image, v),
				Ref:       registry + wl.image + "@" + d,
				Digest:    d,
			}
			c.Cluster, c.Namespace, c.Kind, c.Name = clusters[env], wl.ns, wl.kind, wl.name
			c.Exposure = demoExposure[wl.name]
			if c.Exposure == "" {
				c.Exposure = model.ExposureNone
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// step applies one change: a new release in dev, or a promotion.
func (s *Source) step() {
	wl := workloads[s.rng.IntN(len(workloads))]
	key := func(env string) string { return env + "/" + wl.name }
	if len(wl.envs) == 1 {
		s.versions[key("ops")]++
		return
	}
	switch r := s.rng.IntN(100); {
	case r < 45 && s.versions[key("dev")] < 16:
		s.versions[key("dev")]++
	case r < 75 && s.versions[key("test")] < s.versions[key("dev")]:
		s.versions[key("test")] = s.versions[key("dev")]
	case s.versions[key("prod")] < s.versions[key("test")]:
		s.versions[key("prod")] = s.versions[key("test")]
		if wl.ns == "ingress" || wl.ns == "kube-system" {
			s.versions[key("ops")] = s.versions[key("prod")]
		}
	default:
		s.versions[key("dev")]++
	}
}

// ---- scanner ----------------------------------------------------------------

type vuln struct {
	id, pkg     string
	intro, fix  int // affected package versions: intro <= v < fix (fix < 0: no fix)
	severity    model.Severity
	cvss, epss  float64
	gen, kevGen int // DB generation it appears in / becomes KEV in (-1: never)
	desc        string
}

var flaws = []string{
	"Buffer overflow", "Denial of service", "Remote code execution", "Authentication bypass",
	"Information disclosure", "Unsafe deserialization", "Path traversal", "HTTP header injection",
}

func catalog() []vuln {
	r := rand.New(rand.NewPCG(2099, 1))
	pkgs := map[string]bool{}
	var names []string
	for _, wl := range workloads {
		for _, p := range wl.pkgs {
			if !pkgs[p] {
				pkgs[p] = true
				names = append(names, p)
			}
		}
	}
	var out []vuln
	for i := range 48 {
		p := names[i%len(names)]
		v := vuln{id: fmt.Sprintf("CVE-2099-%04d", i+1), pkg: p, intro: r.IntN(9), kevGen: -1}
		v.fix = v.intro + 2 + r.IntN(4)
		if r.IntN(5) == 0 {
			v.fix = -1
		}
		switch x := r.IntN(100); {
		case x < 12:
			v.severity, v.cvss = model.Critical, 9+r.Float64()
		case x < 40:
			v.severity, v.cvss = model.High, 7+2*r.Float64()
		case x < 80:
			v.severity, v.cvss = model.Medium, 4+3*r.Float64()
		default:
			v.severity, v.cvss = model.Low, 1+3*r.Float64()
		}
		v.epss = r.Float64() * r.Float64() * r.Float64()
		if i >= 36 {
			v.gen = i - 35 // published by later DB updates
		}
		v.desc = fmt.Sprintf("[Demo] %s in %s.", flaws[r.IntN(len(flaws))], p)
		out = append(out, v)
	}
	// Exploited vulns are severe ones: two known from the start, then one
	// entering the KEV catalog at DB updates 2, 4 and 6.
	kevGens := []int{0, 0, 2, 4, 6}
	for i := range out {
		if len(kevGens) > 0 && out[i].gen == 0 && out[i].severity.Rank() >= model.High.Rank() {
			out[i].kevGen, kevGens = kevGens[0], kevGens[1:]
		}
	}
	return out
}

type image struct {
	wl      workload
	release int
}

// Scanner fakes syft and grype. Every DBEvery its DB "publishes" new CVEs.
type Scanner struct {
	DBEvery time.Duration

	mu     sync.Mutex
	vulns  []vuln
	gen    int
	built  time.Time
	images map[string]image
}

func NewScanner(dbEvery time.Duration) *Scanner {
	s := &Scanner{DBEvery: dbEvery, vulns: catalog(), built: time.Now().UTC().Truncate(time.Second), images: map[string]image{}}
	for _, wl := range workloads {
		for v := range 40 {
			s.images[digestOf(wl.name, v)] = image{wl, v}
		}
	}
	return s
}

type sbomDoc struct {
	Image    string          `json:"image"`
	Packages []model.Package `json:"packages"`
	Source   struct {        // like syft-json, for scan.Provenance
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	} `json:"source"`
}

func (s *Scanner) SBOM(ctx context.Context, ref string) ([]byte, error) {
	i := strings.LastIndex(ref, "@")
	img, ok := s.images[ref[i+1:]]
	if i < 0 || !ok {
		return nil, fmt.Errorf("demo: unknown image %s", ref)
	}
	// A private image the scanner has no pull access to, to exercise failures.
	if img.wl.name == "minio" {
		return nil, fmt.Errorf("syft scan: exit status 1: …oci-registry: failed to get image descriptor from registry: GET https://%stoken?…: DENIED: requested access to the resource is denied", registry)
	}
	select { // pulling and cataloging takes a while
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(time.Duration(2000+rand.IntN(4000)) * time.Millisecond):
	}
	doc := sbomDoc{Image: ref}
	if img.wl.source != "" {
		doc.Source.Metadata.Labels = map[string]string{
			"org.opencontainers.image.source":   img.wl.source,
			"org.opencontainers.image.revision": fmt.Sprintf("%016x", hash(fmt.Sprintf("%s/%d", img.wl.name, img.release))),
		}
	}
	for _, p := range img.wl.pkgs {
		v := fmt.Sprintf("1.%d.0", pkgVersion(img.wl, p, img.release))
		doc.Packages = append(doc.Packages, model.Package{Name: p, Version: v, Type: pkgType(p), PURL: purl(p, v)})
	}
	return json.Marshal(doc)
}

func (s *Scanner) Match(ctx context.Context, sbom []byte) (scan.Result, error) {
	var doc sbomDoc
	if err := json.Unmarshal(sbom, &doc); err != nil {
		return scan.Result{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res := scan.Result{DBBuilt: s.built}
	for _, p := range doc.Packages {
		var pv int
		fmt.Sscanf(p.Version, "1.%d.0", &pv)
		for _, v := range s.vulns {
			if v.pkg != p.Name || v.gen > s.gen || pv < v.intro || (v.fix >= 0 && pv >= v.fix) {
				continue
			}
			kev := v.kevGen >= 0 && v.kevGen <= s.gen
			cvss, epss, pct := v.cvss, v.epss, min(v.epss*4, 0.99)
			m := model.Match{
				Vuln: model.Vuln{
					ID: v.id, Aliases: []string{}, Severity: v.severity, CVSS: &cvss, EPSS: &epss, EPSSPercentile: &pct,
					KEV: &kev, Description: v.desc, URL: "#",
				},
				Pkg:      p,
				Source:   demoSource(p.Type),
				Location: demoLocation(p),
			}
			if kev {
				added := s.built
				m.Vuln.KEVAddedAt = &added
			}
			if v.fix >= 0 {
				m.FixedIn = []string{fmt.Sprintf("1.%d.0", v.fix)}
			}
			res.Matches = append(res.Matches, m)
		}
	}
	// A typical binary classifier misidentification: it reads the wrong
	// version string, and the major differs from the tag.
	if strings.Contains(doc.Image, "/traefik@") {
		cvss, epss := 9.8, 0.4
		kev := false
		res.Matches = append(res.Matches, model.Match{
			Vuln: model.Vuln{ID: "CVE-2099-0999", Aliases: []string{}, Severity: model.Critical, CVSS: &cvss, EPSS: &epss,
				KEV: &kev, Description: "[Demo] Remote code execution in traefik 2.x.", URL: "#"},
			Pkg:      model.Package{Name: "traefik", Version: "2.25.7", Type: "binary", PURL: "pkg:generic/traefik@2.25.7"},
			FixedIn:  []string{"2.26.0"},
			Source:   model.SourceHeuristic,
			Location: "/traefik",
		})
	}
	return res, nil
}

func demoSource(pkgType string) string {
	switch pkgType {
	case "deb":
		return model.SourceOS
	case "go-module":
		return model.SourceBuildInfo
	}
	return model.SourceManifest
}

func demoLocation(p model.Package) string {
	switch p.Type {
	case "deb":
		return "/var/lib/dpkg/status"
	case "go-module":
		return "/usr/local/bin/app"
	case "java-archive":
		return "/app/lib/" + p.Name + "-" + p.Version + ".jar"
	case "npm":
		return "/app/node_modules/" + p.Name + "/package.json"
	}
	return "/usr/lib/python3/site-packages/" + p.Name
}

func (s *Scanner) UpdateDB(ctx context.Context) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.built) >= s.DBEvery && s.gen < 12 {
		s.gen++
		s.built = time.Now().UTC().Truncate(time.Second)
	}
	return s.built, nil
}
