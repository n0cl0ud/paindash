# Design decisions

Why paindash is built the way it is. Each entry: the decision, why, and what it implies. Read this
before changing one of them; add an entry when you make a new structural choice.

## Inventory and scanning

### 1. Inventory from kube-state-metrics through PromQL
**Decision.** Read `kube_pod_container_info` (and owner, Ingress, Service, endpoint series) through a
Prometheus-compatible API. No agent, operator or Kubernetes API access.
**Why.** Most clusters already run kube-state-metrics and a Prometheus; multi-cluster comes for free
with Thanos or Mimir; `image_id` carries the digest the kubelet actually pulled (tags are mutable).
**Implies.** Prometheus + kube-state-metrics is a prerequisite. The `inventory.Source` interface
leaves room for a Kubernetes API source (roadmap).

### 2. One scan per digest; syft and grype as CLIs built from source
**Decision.** Scan each digest once, whatever the number of workloads, clusters or envs running it.
Run syft and grype as binaries, built from pinned sources (releases at least two weeks old).
**Why.** Their CLIs and JSON outputs are stable while their Go APIs move fast; building from source
lets us use our Go toolchain and override vulnerable dependencies; a compromised scanner would see
every image, hence the delay before upgrades.
**Implies.** `tools/` holds one Go module per scanner; Dependabot proposes bumps, a human applies the
two-week rule.

### 3. Store the SBOM, rematch instead of rescanning
**Decision.** Keep every SBOM (gzipped) in PostgreSQL. When the grype DB changes (checked hourly),
rematch every stored SBOM of a running image.
**Why.** New CVEs show up within the hour without pulling a single layer again; scanning is the
expensive part, matching is cheap.
**Implies.** Changing pruning or matching rules requires bumping `scan.RulesVersion`, which rematches
everything once at startup. Images that stopped running keep their SBOM for the retention period
but are not rematched.

### 4. Retries every 6 h, independent of the DB check
**Decision.** Failed scans are retried at startup and every 6 h; the DB check runs hourly.
**Why.** An image that keeps failing would otherwise fail, and be announced in the live feed,
every hour.

### 5. Workload attribution through owner series, names as a fallback
**Decision.** Walk Pod → ReplicaSet → Deployment and Pod → Job → CronJob. When the owner series is
missing, infer the owner from the controller-made name.
**Why.** During a deletion the ReplicaSet disappears before its pods (and a new one may not be
scraped yet): without the fallback, a pod briefly shows up as a new "ReplicaSet" workload, with
spurious deploy and remove events.

## Data and serving

### 6. PostgreSQL only, single replica
**Decision.** One PostgreSQL database for everything (inventory, SBOMs, findings, events, history,
exceptions); migrations embedded and run at startup; one pod (Recreate).
**Why.** Low operational cost. The scan queue, history writer and grype DB cache assume one pod.
**Implies.** No horizontal scaling; Helm chart pins `replicas: 1`.

### 7. In-memory read model, recomputed on change
**Decision.** Load a `Dataset` when the store version changes, compute views per (env, scope) once,
serve every request from them.
**Why.** Every page needs the same few aggregates; recomputing per request is slow on a large inventory.

### 8. Live updates with SSE and invalidations
**Decision.** One Server-Sent Events stream per env: live events plus "invalidate" messages that
make the UI refetch.
**Why.** One-way updates over plain HTTP, through any proxy, with automatic reconnection.

### 9. Distinct counts per environment
**Decision.** Headline numbers count distinct vulnerabilities per env.
**Implies.** A KEV already present elsewhere in the env does not move the KEV tile when another
workload gets it, while that workload's events show "+1 KEV".

### 10. History coalesced, with what moved it
**Decision.** Record the headline numbers per env when they move (at most every 5 min, after scans
settle) and once a day, each point with the events that explain the change.
**Why.** A readable trend, not a noisy one. A change undone within 5 min never shows.

## Prioritization

### 11. Urgency order
**Decision.** Actively exploited (CISA KEV) first, then severity, exposure (internet first), EPSS.
**Why.** Exploitation in the wild beats theoretical severity; exposure and exploit probability
break ties between equal severities.

### 12. Exposure: three levels, never understated
**Decision.** internet / internal / none, from Ingress classes, LoadBalancer Services (private IP or
"internal" hostname = internal) and Traefik IngressRoute entrypoints. Unknown entrypoints count as
internet-facing (and are logged).
**Why.** Understating exposure is the dangerous mistake; overstating it is merely noisy.
**Implies.** Without routing metrics, or in a cluster with routes but no series leading to its pods,
the UI says "exposure not configured" instead of "none". Services lead to pods through
EndpointSlices (by pod name, host network pods included) and Endpoints (by IP, without them); a
slice name shared by two long Service names gets the widest of their levels.

### 13. Fixed version of the installed release line
**Decision.** Show, for each installed version, the lowest fixed version above it.
**Why.** Advisories list one fix per release line (e.g. 1.10.28, 2.2.28, 2.9.8); the first one of
the list can be a downgrade.

### 14. Promotion along a configured chain
**Decision.** `PAINDASH_PROMOTION` (default dev, test, prod). "Already fixed in X → promote" only
suggests images from earlier envs, filtered server-side.
**Why.** An image from a later env without the vuln is usually older: suggesting it would be a
rollback.

## Exceptions and security

### 15. Exceptions as expiring OpenVEX statements
**Decision.** "Not affected" statements with an OpenVEX justification, a free-text statement, a
scope (vuln + package name, optional namespace or workload) and a mandatory expiry (at most 180
days); exported as an OpenVEX document.
**Why.** A standard auditors know, and no exception lives forever.
**Implies.** They match the package name in any version and in every env; their events (and history
markers) go only to the envs where they cover a container.

### 16. Authentication delegated to Pomerium
**Decision.** No login in the app: verify Pomerium's signed assertion (JWKS); `disabled` mode for
local use, made visible ("No auth" badge, exceptions by "anonymous").
**Why.** Identity-aware proxies do authentication better; header-trust modes are a classic source of
bypasses, so they wait for a deliberate threat model (roadmap).

### 17. Session expiry reloads the page
**Decision.** On a 401 or a login redirect, reload once (not more than once a minute, never while
the exception form is open); otherwise show a banner.
**Why.** The proxy's silent re-login makes a reload enough; a banner for that is friction.

## Fix prompts

### 18. Prompts for coding agents, generated in the browser
**Decision.** Per workload and per vulnerability, a Markdown prompt to paste into Claude Code or
any coding agent: fix, verify, one PR per repo, one-line commits without trailers. Experimental.
**Why.** The fix is usually a dependency or base image bump an agent does well; the dashboard has
all the context.
**Safety.** Scanner data is sanitized and fenced as data; advisory descriptions (external free text)
are left out. First-party is decided from the image path (`ghcr.io/<owner>/…`), never from a label,
so a third-party image never sends anyone to edit a repo. The source repo and commit come from the
OCI `source` and `revision` labels, guessed from the image name otherwise (and flagged).

## Packaging

### 19. v0.1 scope
**Decision.** Ship: Prometheus source, Ingress/LB/Traefik exposure, Pomerium or disabled auth,
minimal Helm chart without bundled PostgreSQL, plain manifests, compose demo, multi-arch image.
Defer: Kubernetes API source, Gateway API, oauth2-proxy headers, cosign signatures.
**Why.** Each generalization built without real users would be subtly wrong; wait for their needs.

### 20. Multi-arch through cross-compilation
**Decision.** Build stages run on the build platform; Go cross-compiles paindash, syft, grype and
the ECR credential helper for the target platform.
**Why.** Emulated arm64 builds of the scanners take far longer.
