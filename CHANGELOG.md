# Changelog

## 0.1.2

The history follows the scope filters, and the suspect flag no longer depends on the scope.

- History under scope filters: with namespace, component or exposure filters, the four history lines
  are recounted for that scope and end on its KPI tiles ("Filtered · since" the first recorded
  facts). paindash now records what the numbers are made of, per vulnerability, package and
  workload, as validity intervals (new table `history_facts`, written only on change); a filtered
  history starts with this release and has no change markers. `/api/history` accepts `ns`, `wl` and
  `exp`.
- History panel: when the history is younger than the range, the trend says since when (e.g.
  "since Oct 26").
- Fix: a finding is flagged suspect (misidentified package) from each container's own version and
  image. It used to compare the group's first version with every image, so the flag changed with
  the scope and could miss a container whose own version was misidentified.

## 0.1.1

A hardened image, and fixes for many environments and the install steps.

- Install: the snapshot check reads the pod's log, as `kubectl run --rm -i` could lose its output.
- Environment switcher: wraps when the environments do not fit the width (a phone) instead of
  widening the page; only the first nine announce a key, as only keys 1 to 9 switch.
- Image: Chainguard static base (Wolfi) instead of Alpine: no shell (`kubectl debug` to look
  inside), no package manager, no libc, only a current CA bundle, time zones and base files. Every
  build input is pinned by digest, BuildKit included.

## 0.1.0

First public release.

- Inventory of the images actually running, from kube-state-metrics through any Prometheus-compatible
  API; several clusters and environments by series labels, or a single Prometheus with defaults.
  Basic auth, a bearer token file (re-read at each sync), extra headers such as `X-Scope-OrgID`, and
  a private CA for that API.
- One scan per digest (syft SBOM stored, grype match), hourly vulnerability DB check and rematch of
  every stored SBOM, CISA KEV and FIRST EPSS enrichment.
- Exposure from Ingresses (by class), LoadBalancer Services and Traefik IngressRoutes, followed to
  the pods through EndpointSlices (the kube-state-metrics default since v2.18.0) or Endpoints.
- UI: To fix, Workloads, All vulnerabilities, Exceptions; scopes by namespace, component and
  exposure; promotion hints along a configurable chain; history per environment; live feed.
- Exceptions as expiring OpenVEX "not affected" statements, exported as an OpenVEX document.
- Fix prompts (experimental) per workload and per vulnerability, for coding agents.
- Prometheus metrics per environment and workload.
- Sign-in through Pomerium (its signed assertion), OpenID Connect (authorization code with PKCE) or
  local accounts from a file of bcrypt hashes (`paindash hash-password`; `*` in front of a hash
  locks an account), the last two kept in an encrypted session cookie; a "Sign out" button.
- Read-only users: `PAINDASH_EDITOR_GROUPS` limits who records and revokes exceptions, in every
  authentication mode.
- Helm chart, plain manifests, docker compose demo; amd64 and arm64 images.
