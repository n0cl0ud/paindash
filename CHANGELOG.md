# Changelog

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
