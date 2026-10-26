// API contract between the Go backend (internal/api) and the React UI.
// Keep in sync with internal/model/model.go. All timestamps are RFC 3339 strings.
//
// Scope: /api/summary, /api/findings, /api/workloads and /api/images accept three optional
// params that restrict everything they compute (KPIs, findings, workloads,
// promotion hints) to the matching containers, with unchanged shapes:
//   ns=checkout,catalog                     namespace in the list
//   wl=checkout/checkout-api,edge/edge-api  "namespace/name" in the list
//   exp=internet,internal                   exposure in the list (see Exposure)
// Several set = AND. /api/events and /api/stream are not scoped (the UI filters
// the live feed itself).

export type Severity =
  | "Critical"
  | "High"
  | "Medium"
  | "Low"
  | "Negligible"
  | "Unknown";

export const SEVERITIES: Severity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Negligible",
  "Unknown",
];

// How a workload can be reached, from the Traefik IngressRoutes and the
// LoadBalancer Services that route to its pods:
//  internet: a public Ingress class or Traefik entrypoint, or an internet-facing LoadBalancer
//  internal: only internal entrypoints (websecure-internal...) or internal LoadBalancers
//  none: no route found. Apps behind Pomerium show as "none" (the route targets
//        Pomerium itself).
export type Exposure = "internet" | "internal" | "none";

export interface EnvInfo {
  name: string; // "prod" | "test" | "dev" | "ops" (ordered for the switcher)
  clusters: string[];
}

// GET /api/meta
export interface Meta {
  envs: EnvInfo[];
  user: { email: string; groups: string[]; canEdit: boolean } | null; // canEdit: may record and revoke exceptions
  vulnDb: { builtAt: string | null; checkedAt: string | null };
  inventory: { source: "prometheus" | "demo"; lastSyncAt: string | null };
  exposureAvailable: boolean; // false when no Ingress, IngressRoute or LoadBalancer metrics are found
  demo: boolean;
  gitopsRepo: string; // GitHub "owner/name" of the cluster manifests (fix prompt), "" if not set
  promotion: string[]; // envs in the order fixes are promoted, e.g. ["dev", "test", "prod"]
  authDisabled: boolean; // anyone reaching the port is served
  signOut: boolean; // paindash holds the session (oidc, local): POST /auth/logout signs out
}

// Scope params, on summary, findings, workloads and images:
//   ns=a,b  wl=ns/name,…  exp=internet,internal,none (exposure)
// GET /api/summary?env=prod[&ns=…&wl=…&exp=…]
export interface Summary {
  env: string;
  kev: number; // distinct vulns listed in CISA KEV affecting running workloads
  criticalFixable: number; // distinct Critical vulns with a fix available
  bySeverity: Record<Severity, number>; // distinct (vuln, package) pairs
  workloadsAffected: number; // workloads with >= 1 High/Critical
  workloadsTotal: number;
  internetAffected: number; // internet-facing workloads with >= 1 High/Critical
  highFixableInternet: number; // distinct High vulns with a fix, on internet-facing workloads
  images: { total: number; scanned: number; pending: number; failed: number };
  // Findings left out of every count above (and of the default findings list):
  suspect: number; // identification looks wrong (see Finding.suspect)
  excepted: number; // fully covered by an active exception
  exceptionsExpiring: number; // active exceptions (all envs) expiring within 14 days
}

export interface WorkloadRef {
  cluster: string;
  namespace: string;
  kind: string; // Deployment | StatefulSet | DaemonSet | CronJob | Job | Pod
  name: string;
}

export interface AffectedContainer extends WorkloadRef {
  exposure: Exposure;
  container: string;
  image: string; // reference as deployed (tag or digest)
  digest: string; // sha256:...
}

// Another env runs the same workload (namespace/kind/name/container) with an
// image that does NOT have this vuln: "already fixed in test -> promote".
export interface PromotionHint {
  env: string;
  cluster: string;
  image: string;
  digest: string;
}

// How the vulnerable package was identified in the image, from most to least
// reliable: the OS package database (apk/dpkg/rpm), build metadata compiled
// into a binary (Go build info, Rust cargo-auditable), a language manifest
// (pom.properties, package.json, dist-info...), or a heuristic (version string
// pattern-matched in a binary without metadata).
export type FindingSource = "os" | "build-info" | "manifest" | "heuristic" | "unknown";

export interface Finding {
  vulnId: string; // CVE-... or GHSA-...
  aliases: string[];
  severity: Severity;
  cvss: number | null;
  epss: number | null; // probability 0..1
  epssPercentile: number | null; // 0..1
  kev: boolean;
  kevAddedAt: string | null;
  description: string;
  url: string; // advisory link
  package: { name: string; version: string; type: string; purl: string };
  fixedIn: string[]; // empty => no fix available
  firstSeen: string; // first time this vuln was seen in this env
  // Partly excepted finding (exception null): only the workloads not covered.
  // Fully excepted finding (exception set): all the excepted workloads.
  exposure: Exposure; // the widest exposure among its workloads
  workloads: AffectedContainer[];
  promotion: PromotionHint[];
  source: FindingSource;
  location: string; // file the package was found in, e.g. "/traefik" or "/app/lib/x.jar"
  // The package is named like the image but its major version differs from the
  // image tag (e.g. "traefik 1.24.4" in traefik:v3.4.1): likely misidentified.
  suspect: boolean;
  exception: Exception | null; // set when every affected workload is excepted
}

// GET /api/findings?env=prod&severity=Critical,High&kev=1&fixable=1&q=openssl&limit=200[&ns=…&wl=…]
//   &include=suspect,excepted  also return suspect and/or fully excepted findings
//   (left out by default, like in the summary counts).
export interface FindingsResponse {
  items: Finding[];
  total: number;
}

// Where to fix an image: in its source repo when we build it (first-party,
// decided from the image path), by bumping it in the GitOps repo otherwise.
export interface ImageOrigin {
  firstParty: boolean;
  repo: string; // GitHub "owner/name" (the upstream project when third-party), "" if unknown
  revision: string; // commit the image was built from (OCI label), "" if unknown
  guessed: boolean; // repo inferred from the image name: the image has no source label
}

export interface WorkloadContainer {
  name: string;
  image: string;
  digest: string;
  origin?: ImageOrigin; // workload detail only
}

export interface Workload extends WorkloadRef {
  env: string;
  exposure: Exposure;
  containers: WorkloadContainer[];
  counts: Record<Severity, number>;
  kev: number;
  fixable: number;
  lastChangeAt: string; // last time an image of this workload changed
}

// GET /api/workloads?env=prod[&ns=…&wl=…]
export interface WorkloadsResponse {
  items: Workload[];
}

// GET /api/workloads/{cluster}/{namespace}/{kind}/{name}
export interface WorkloadDetail {
  workload: Workload;
  findings: Finding[];
}

export interface ImageScan {
  image: string; // reference as deployed (tag or digest)
  digest: string; // sha256:...
  status: "pending" | "scanning" | "scanned" | "failed";
  error: string; // last failure message (also set while a retry is pending); "" if none
  attempts: number;
  workloads: AffectedContainer[]; // workloads running this image in that env
}

// GET /api/images?env=prod&status=failed (default) | status=pending (pending + scanning)[&ns=…&wl=…]
export interface ImagesResponse {
  items: ImageScan[]; // failed first, then by image
}

// GET /api/origins: where every running image comes from (all envs), by digest.
export interface OriginsResponse {
  items: Record<string, ImageOrigin>;
}

// ---- Exceptions (OpenVEX "not_affected" statements) ----------------------------

export type VexJustification =
  | "component_not_present"
  | "vulnerable_code_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

export const VEX_JUSTIFICATIONS: VexJustification[] = [
  "component_not_present",
  "vulnerable_code_not_present",
  "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary",
  "inline_mitigations_already_exist",
];

export interface Exception {
  id: number;
  vulnId: string;
  package: string; // package name
  namespace: string; // "" = any namespace
  workload: string; // "" = any workload of the namespace (or anywhere)
  justification: VexJustification;
  statement: string; // why, in plain words
  author: string; // email from the Pomerium identity
  createdAt: string;
  expiresAt: string; // mandatory, at most 180 days after creation
  revokedAt: string | null;
  revokedBy: string | null;
  state: "active" | "expiring" | "expired" | "revoked"; // expiring = active, < 14 days left
}

// GET  /api/exceptions                   -> { items: Exception[] } (active first)
// POST /api/exceptions        ExceptionInput -> Exception (201); 400 with { error } on invalid input
// POST /api/exceptions/{id}/revoke       -> Exception
// GET  /api/exceptions/openvex           -> OpenVEX document (for auditors)
// Writes need Content-Type: application/json.
export interface ExceptionInput {
  vulnId: string;
  package: string;
  namespace?: string;
  workload?: string; // requires namespace
  justification: VexJustification;
  statement: string; // >= 10 characters
  expiresAt: string; // RFC 3339, in the future, <= 180 days
}

export interface ExceptionsResponse {
  items: Exception[];
}

export type LiveEventType =
  | "deployed" // a workload now runs a new image
  | "removed" // a workload/container disappeared
  | "scan_completed"
  | "scan_failed"
  | "vulns_new" // new findings on running images (new deploy or DB refresh)
  | "vulns_fixed" // findings gone (redeploy with fixed image)
  | "kev_added" // a vuln affecting running workloads entered CISA KEV
  | "db_updated" // vulnerability database refreshed
  | "exception_added"
  | "exception_revoked"
  | "exception_expired"; // the finding is back in the lists

export interface LiveEvent {
  id: number;
  ts: string;
  env: string;
  cluster: string;
  type: LiveEventType;
  title: string; // human readable, English (shown as is)
  severity: Severity | null; // highest severity involved, for coloring
  workload: WorkloadRef | null;
  image: string | null;
  delta: { added: number; removed: number; kev: number } | null;
}

// GET /api/history?days=30[&ns=…&wl=…&exp=…]
// Headline numbers per env over time, counted like the summary tiles. Each
// series ends with a live point at `now` (the tiles' values). Under a scope,
// the points are recounted from the facts recorded since scopedSince[env],
// without change markers; an env with no facts yet has an empty series.
export interface HistoryChange {
  t: string;
  type: LiveEventType;
  title: string;
  delta?: { added: number; removed: number; kev: number } | null;
}

export interface HistoryPoint {
  t: string;
  kev: number;
  criticalFixable: number;
  highFixableInternet: number;
  excepted: number;
  changes: HistoryChange[]; // events since the previous point that explain the move
}

export interface HistoryResponse {
  since: string; // start of the window
  start: string | null; // oldest point recorded, null if none
  now: string;
  envs: Record<string, HistoryPoint[]>; // oldest first
  scopedSince: Record<string, string> | null; // per env, when its facts begin; null without a scope
}

// GET /api/events?env=prod&limit=50
export interface EventsResponse {
  items: LiveEvent[];
}

// GET /api/stream?env=prod  (Server-Sent Events)
//   event: live        data: LiveEvent
//   event: invalidate  data: {"scopes": ("summary"|"findings"|"workloads")[]}
//   ": ping" comment every 15s (heartbeat)
export interface InvalidateMessage {
  scopes: ("summary" | "findings" | "workloads")[];
}
