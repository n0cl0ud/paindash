// Package model holds the types shared by the store, the pipeline and the
// HTTP API. JSON names follow the UI contract in web/src/api/types.ts.
package model

import (
	"strings"
	"time"
)

type Severity string

const (
	Critical   Severity = "Critical"
	High       Severity = "High"
	Medium     Severity = "Medium"
	Low        Severity = "Low"
	Negligible Severity = "Negligible"
	Unknown    Severity = "Unknown"
)

// Severities is ordered from worst to least severe.
var Severities = []Severity{Critical, High, Medium, Low, Negligible, Unknown}

// Rank orders severities: higher is worse.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 5
	case High:
		return 4
	case Medium:
		return 3
	case Low:
		return 2
	case Negligible:
		return 1
	}
	return 0
}

func ParseSeverity(s string) Severity {
	for _, sev := range Severities {
		if strings.EqualFold(s, string(sev)) {
			return sev
		}
	}
	return Unknown
}

// SeverityCounts always carries every severity so the UI gets a full record.
func SeverityCounts() map[Severity]int {
	m := make(map[Severity]int, len(Severities))
	for _, s := range Severities {
		m[s] = 0
	}
	return m
}

type WorkloadRef struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

func (w WorkloadRef) Key() string {
	return w.Cluster + "/" + w.Namespace + "/" + w.Kind + "/" + w.Name
}

// How a workload can be reached.
const (
	ExposureInternet = "internet" // public entrypoint or internet-facing LoadBalancer
	ExposureInternal = "internal" // internal entrypoints or LoadBalancers only
	ExposureNone     = "none"
)

// ExposureRank orders exposures: higher is wider.
func ExposureRank(e string) int {
	switch e {
	case ExposureInternet:
		return 2
	case ExposureInternal:
		return 1
	}
	return 0
}

// WiderExposure returns the widest of two exposures.
func WiderExposure(a, b string) string {
	if ExposureRank(b) > ExposureRank(a) {
		return b
	}
	if a == "" {
		return ExposureNone
	}
	return a
}

// Container is one (workload, container, digest) tuple running in a cluster.
// During a rollout a workload container can run two digests at once.
type Container struct {
	Env string
	WorkloadRef
	Container string
	Image     string // reference as deployed (tag or digest)
	Ref       string // pullable reference repo@sha256:...
	Digest    string
	Exposure  string
	FirstSeen time.Time
	LastSeen  time.Time
	Source    string // OCI label org.opencontainers.image.source, "" if unknown
	Revision  string // OCI label org.opencontainers.image.revision
}

func (c Container) Key() string {
	return c.WorkloadRef.Key() + "/" + c.Container + "@" + c.Digest
}

// SlotKey identifies the workload container regardless of the image it runs.
func (c Container) SlotKey() string {
	return c.WorkloadRef.Key() + "/" + c.Container
}

// PromotionKey identifies the same workload container across clusters/envs.
func (c Container) PromotionKey() string {
	return c.Namespace + "/" + c.Kind + "/" + c.Name + "/" + c.Container
}

type Vuln struct {
	ID             string
	Aliases        []string
	Severity       Severity
	CVSS           *float64
	EPSS           *float64
	EPSSPercentile *float64
	KEV            *bool // nil: unknown, leave the stored value untouched
	KEVAddedAt     *time.Time
	Description    string
	URL            string
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl"`
}

// How a package was identified in an image, from most to least reliable.
const (
	SourceOS        = "os"         // OS package database (apk, dpkg, rpm)
	SourceBuildInfo = "build-info" // metadata compiled into a binary (Go, Rust auditable)
	SourceManifest  = "manifest"   // language manifest (pom.properties, package.json...)
	SourceHeuristic = "heuristic"  // version string pattern-matched in a binary
	SourceUnknown   = "unknown"
)

// Match is one vulnerability found in one package of an SBOM.
type Match struct {
	Vuln     Vuln
	Pkg      Package
	FixedIn  []string
	Source   string
	Location string // file the package was found in
}

// FindingRow is a stored match for an image digest.
type FindingRow struct {
	VulnID    string
	Pkg       Package
	FixedIn   []string
	FirstSeen time.Time
	Source    string
	Location  string
}

// VulnRef is the minimal view of a vuln used to describe changes in events.
type VulnRef struct {
	ID       string
	Severity Severity
	KEV      bool
}

// Dataset is everything the read API needs, loaded in one go and cached.
type Dataset struct {
	Containers  []Container             // all envs
	Findings    map[string][]FindingRow // by image digest
	Vulns       map[string]Vuln
	ImageStatus map[string]string // digest -> pending|scanning|scanned|failed
	ImageErrors map[string]ImageError
	Exceptions  []Exception // active ones only
	State       map[string]string
	// Unscoped is the full dataset a scoped one was cut from: promotion hints
	// look for fixes in every env, whatever the scope.
	Unscoped *Dataset
}

// ImageError is the last scan failure of an image.
type ImageError struct {
	Error    string
	Attempts int
}

// ---- API payloads -----------------------------------------------------------

type EnvInfo struct {
	Name     string   `json:"name"`
	Clusters []string `json:"clusters"`
}

type User struct {
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	// CanEdit: may record and revoke exceptions (PAINDASH_EDITOR_GROUPS).
	CanEdit bool `json:"canEdit"`
}

type Meta struct {
	Envs   []EnvInfo `json:"envs"`
	User   *User     `json:"user"`
	VulnDB struct {
		BuiltAt   *time.Time `json:"builtAt"`
		CheckedAt *time.Time `json:"checkedAt"`
	} `json:"vulnDb"`
	Inventory struct {
		Source     string     `json:"source"`
		LastSyncAt *time.Time `json:"lastSyncAt"`
	} `json:"inventory"`
	ExposureAvailable bool   `json:"exposureAvailable"`
	Demo              bool   `json:"demo"`
	GitOpsRepo        string `json:"gitopsRepo"` // GitHub "owner/name" of the cluster manifests
	// Envs in the order fixes are promoted (e.g. dev, test, prod).
	Promotion    []string `json:"promotion"`
	AuthDisabled bool     `json:"authDisabled"`
	// SignOut: paindash holds the session (oidc, local) and signs out with
	// POST /auth/logout.
	SignOut bool `json:"signOut"`
}

type ImageCounts struct {
	Total   int `json:"total"`
	Scanned int `json:"scanned"`
	Pending int `json:"pending"`
	Failed  int `json:"failed"`
}

type Summary struct {
	Env               string           `json:"env"`
	KEV               int              `json:"kev"`
	CriticalFixable   int              `json:"criticalFixable"`
	BySeverity        map[Severity]int `json:"bySeverity"`
	WorkloadsAffected int              `json:"workloadsAffected"`
	WorkloadsTotal    int              `json:"workloadsTotal"`
	InternetAffected  int              `json:"internetAffected"`
	// Distinct high vulnerabilities with a fix, on internet-facing workloads.
	HighFixableInternet int         `json:"highFixableInternet"`
	Images              ImageCounts `json:"images"`
	// Left out of the counts above and of the default findings list.
	Suspect            int `json:"suspect"`
	Excepted           int `json:"excepted"`
	ExceptionsExpiring int `json:"exceptionsExpiring"`
}

type AffectedContainer struct {
	WorkloadRef
	Exposure  string `json:"exposure"`
	Container string `json:"container"`
	Image     string `json:"image"`
	Digest    string `json:"digest"`
}

type PromotionHint struct {
	Env     string `json:"env"`
	Cluster string `json:"cluster"`
	Image   string `json:"image"`
	Digest  string `json:"digest"`
}

type Finding struct {
	VulnID         string              `json:"vulnId"`
	Aliases        []string            `json:"aliases"`
	Severity       Severity            `json:"severity"`
	CVSS           *float64            `json:"cvss"`
	EPSS           *float64            `json:"epss"`
	EPSSPercentile *float64            `json:"epssPercentile"`
	KEV            bool                `json:"kev"`
	KEVAddedAt     *time.Time          `json:"kevAddedAt"`
	Description    string              `json:"description"`
	URL            string              `json:"url"`
	Package        Package             `json:"package"`
	FixedIn        []string            `json:"fixedIn"`
	FirstSeen      time.Time           `json:"firstSeen"`
	Exposure       string              `json:"exposure"`
	Workloads      []AffectedContainer `json:"workloads"`
	Promotion      []PromotionHint     `json:"promotion"`
	Source         string              `json:"source"`
	Location       string              `json:"location"`
	Suspect        bool                `json:"suspect"`
	Exception      *Exception          `json:"exception"`
}

// VEX justifications (OpenVEX "not_affected").
var VexJustifications = []string{
	"component_not_present",
	"vulnerable_code_not_present",
	"vulnerable_code_not_in_execute_path",
	"vulnerable_code_cannot_be_controlled_by_adversary",
	"inline_mitigations_already_exist",
}

// Exception is an OpenVEX "not_affected" statement for a vuln in a package,
// optionally limited to a namespace or a workload, that always expires.
type Exception struct {
	ID            int64      `json:"id"`
	VulnID        string     `json:"vulnId"`
	Package       string     `json:"package"`
	Namespace     string     `json:"namespace"`
	Workload      string     `json:"workload"`
	Justification string     `json:"justification"`
	Statement     string     `json:"statement"`
	Author        string     `json:"author"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	RevokedAt     *time.Time `json:"revokedAt"`
	RevokedBy     *string    `json:"revokedBy"`
	State         string     `json:"state"`
}

// ExpiringWithin is how early an active exception is flagged as expiring.
const ExpiringWithin = 14 * 24 * time.Hour

// StateAt derives the state of an exception at a point in time.
func (e Exception) StateAt(now time.Time) string {
	switch {
	case e.RevokedAt != nil:
		return "revoked"
	case !e.ExpiresAt.After(now):
		return "expired"
	case e.ExpiresAt.Sub(now) < ExpiringWithin:
		return "expiring"
	}
	return "active"
}

// Covers reports whether the exception applies to a vuln in a package of a
// running container.
func (e Exception) Covers(vulnID, pkg string, c AffectedContainer) bool {
	return e.VulnID == vulnID && e.Package == pkg &&
		(e.Namespace == "" || e.Namespace == c.Namespace) &&
		(e.Workload == "" || e.Workload == c.Name)
}

type WorkloadContainer struct {
	Name   string       `json:"name"`
	Image  string       `json:"image"`
	Digest string       `json:"digest"`
	Origin *ImageOrigin `json:"origin,omitempty"` // workload detail only
}

// ImageOrigin tells where to fix an image: in its source repo when we build
// it, by bumping it in the GitOps repo otherwise.
type ImageOrigin struct {
	FirstParty bool   `json:"firstParty"` // built by one of our GitHub owners
	Repo       string `json:"repo"`       // GitHub "owner/name" (upstream when third-party), "" if unknown
	Revision   string `json:"revision"`   // commit the image was built from, "" if unknown
	Guessed    bool   `json:"guessed"`    // repo inferred from the image name: no source label
}

type Workload struct {
	WorkloadRef
	Env          string              `json:"env"`
	Exposure     string              `json:"exposure"`
	Containers   []WorkloadContainer `json:"containers"`
	Counts       map[Severity]int    `json:"counts"`
	KEV          int                 `json:"kev"`
	Fixable      int                 `json:"fixable"`
	LastChangeAt time.Time           `json:"lastChangeAt"`
}

// ImageScan is the scan state of one image running in an env.
type ImageScan struct {
	Image     string              `json:"image"` // reference as deployed
	Digest    string              `json:"digest"`
	Status    string              `json:"status"` // pending|scanning|scanned|failed
	Error     string              `json:"error"`  // last failure, also kept while a retry is pending
	Attempts  int                 `json:"attempts"`
	Workloads []AffectedContainer `json:"workloads"`
}

type WorkloadDetail struct {
	Workload Workload  `json:"workload"`
	Findings []Finding `json:"findings"`
}

type EventType string

const (
	EventDeployed      EventType = "deployed"
	EventRemoved       EventType = "removed"
	EventScanCompleted EventType = "scan_completed"
	EventScanFailed    EventType = "scan_failed"
	EventVulnsNew      EventType = "vulns_new"
	EventVulnsFixed    EventType = "vulns_fixed"
	EventKEVAdded      EventType = "kev_added"
	EventDBUpdated     EventType = "db_updated"
	EventExceptionAdd  EventType = "exception_added"
	EventExceptionRev  EventType = "exception_revoked"
	EventExceptionExp  EventType = "exception_expired"
)

// AllEnvs is the env of events that concern every environment.
const AllEnvs = "*"

type Delta struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	KEV     int `json:"kev"`
}

// HistoryPoint is an env's headline numbers at a time, counted like the
// summary tiles, with the events since the previous point that explain the move.
type HistoryPoint struct {
	At                  time.Time       `json:"t"`
	KEV                 int             `json:"kev"`
	CriticalFixable     int             `json:"criticalFixable"`
	HighFixableInternet int             `json:"highFixableInternet"`
	Excepted            int             `json:"excepted"`
	Changes             []HistoryChange `json:"changes"`
}

// SameNumbers reports whether two points have the same headline numbers.
func (p HistoryPoint) SameNumbers(o HistoryPoint) bool {
	return p.KEV == o.KEV && p.CriticalFixable == o.CriticalFixable &&
		p.HighFixableInternet == o.HighFixableInternet && p.Excepted == o.Excepted
}

type HistoryChange struct {
	At    time.Time `json:"t"`
	Type  EventType `json:"type"`
	Title string    `json:"title"`
	Delta *Delta    `json:"delta,omitempty"`
}

type LiveEvent struct {
	ID       int64        `json:"id"`
	TS       time.Time    `json:"ts"`
	Env      string       `json:"env"`
	Cluster  string       `json:"cluster"`
	Type     EventType    `json:"type"`
	Title    string       `json:"title"`
	Severity *Severity    `json:"severity"`
	Workload *WorkloadRef `json:"workload"`
	Image    *string      `json:"image"`
	Delta    *Delta       `json:"delta"`
}
