# paindash

The CVEs of what **actually runs** on your Kubernetes clusters, per environment, in real time.

paindash reads the image digests your kubelets pulled (from kube-state-metrics, through
Prometheus), scans each image once with [syft](https://github.com/anchore/syft) and
[grype](https://github.com/anchore/grype), and rematches every stored SBOM whenever the
vulnerability database changes. New CVEs show up without a redeploy or a rescan.

![Workloads in prod](docs/screenshots/workloads.png)

> **Prerequisites.** kube-state-metrics, and a Prometheus-compatible query API holding its series
> (Prometheus, Thanos, Mimir, Grafana Cloud...). Several clusters or environments are told apart
> by labels on the series. PostgreSQL 14+. Pull credentials for your private registries.
> paindash needs no access to the Kubernetes API.

## Try it

The demo simulates four clusters, a scanner and a vulnerability database (`CVE-2099-*`):
releases land in dev, get promoted to test then prod, and new CVEs come out every two minutes.

```sh
docker compose --profile demo up --build
```

Then open http://localhost:8080.

## What it does

- **What runs, nothing else.** The digest the kubelet pulled, not the tag or what git says. An image
  promoted from test to prod is analyzed once.
- **Real time.** A deployment shows up in the live feed within about 30 s. A CVE published upstream
  shows up within the hour (the grype database is checked hourly and every SBOM rematched).
- **Actionable.**
  - Sorted by urgency: actively exploited (CISA KEV) first, then severity, exposure and EPSS.
  - The fixed version of the release line you run, not the first one of the advisory.
  - "Already fixed in test → promote" hints along your promotion chain (dev → test → prod).
  - Exposure: internet-facing, internal or not exposed, from Ingresses, LoadBalancer Services and
    Traefik IngressRoutes.
  - Scopes by namespace, component and exposure, kept in the URL.
- **Exceptions as OpenVEX.** "Not affected" statements with a justification, a scope and a
  mandatory expiry; exported as an OpenVEX document for auditors.
- **History.** Per environment: actively exploited, critical with a fix, high with a fix on
  internet-facing workloads, and excepted, with what moved them (deployments, new CVEs, exceptions).
- **Fix prompts** *(experimental)*. On a workload or a vulnerability, a Markdown prompt for Claude
  Code or any coding agent: fix the vulnerabilities and open the pull requests, one per repo. Your
  own images are fixed in their source repo (from the `org.opencontainers.image.source` and
  `.revision` labels), third-party ones bumped in your manifests, or pinned to the image already
  fixed in an earlier environment.
- **Prometheus metrics** on `/metrics`, per environment and workload, for alerting.

| | |
|---|---|
| ![A vulnerability](docs/screenshots/finding.png) | ![Fix prompt](docs/screenshots/fix-prompt.png) |

### Why not Trivy Operator or Kubescape?

They scan from inside each cluster and report per resource. paindash is a single view across
clusters and environments built on the metrics you already collect: no agent or operator in the
clusters, a promotion view ("fixed in test, not in prod yet"), continuous rematching of stored SBOMs
instead of rescans, history, expiring exceptions and prompts to get the fixes done.

## How it works

![How paindash works: kube-state-metrics through Prometheus, inventory, syft, grype, enrichment, read model, outputs](docs/architecture.svg)

More in [docs/architecture.md](docs/architecture.md); how to use it in [docs/guide.md](docs/guide.md).

## Install

With Helm or plain manifests: see [deploy/README.md](deploy/README.md). Check what paindash will
see before installing:

```sh
make snapshot PROMETHEUS_URL=http://localhost:9090
```

## Configuration

Environment variables (the Helm chart maps its values to them).

| Variable | Default | |
|---|---|---|
| `PAINDASH_DATABASE_URL`, or `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGSSLMODE` | — | PostgreSQL 14+ |
| `PAINDASH_PROMETHEUS_URL` | — | Prometheus-compatible API with the kube-state-metrics series; basic auth as `https://user:password@host` |
| `PAINDASH_PROMETHEUS_BEARER_TOKEN_FILE` | — | file holding a bearer token for that API, read at each sync |
| `PAINDASH_PROMETHEUS_CA_FILE` | — | PEM certificates trusted for that API, on top of the system ones |
| `PAINDASH_PROMETHEUS_HEADERS` | — | `Name=value` headers sent to that API, comma-separated (e.g. `X-Scope-OrgID=tenant-1`) |
| `PAINDASH_ENV_LABEL`, `PAINDASH_CLUSTER_LABEL` | `env`, `cluster` | series labels telling environments and clusters apart |
| `PAINDASH_DEFAULT_ENV`, `PAINDASH_DEFAULT_CLUSTER` | —, `default` | for series without those labels (a single Prometheus) |
| `PAINDASH_ENVS` | `prod,test,dev` | environment switcher order; the first one is scanned first |
| `PAINDASH_PROMOTION` | `dev,test,prod` | promotion chain: an image is only suggested from an earlier environment |
| `PAINDASH_PUBLIC_ENTRYPOINTS` | `web,websecure` | Traefik entrypoints reachable from the internet (`*-internal`, `*-int`: internal) |
| `PAINDASH_INGRESS_CLASSES` | — | `class=internet` or `class=internal`, comma-separated; unlisted classes are internal when named `*internal*` or `*private*` |
| `PAINDASH_AUTH` | `pomerium` | `pomerium`, `oidc`, `local`, or `disabled` (see [Security](#security)) |
| `PAINDASH_POMERIUM_JWKS_URL`, `PAINDASH_POMERIUM_AUDIENCE`, `PAINDASH_POMERIUM_ISSUER` | — | verification of `X-Pomerium-Jwt-Assertion` |
| `PAINDASH_PUBLIC_URL` | — | `oidc` and `local`: the URL browsers use (redirect URI, cookies, origin of the sign-in form); https, plain http only on localhost |
| `PAINDASH_OIDC_ISSUER`, `PAINDASH_OIDC_CLIENT_ID`, `PAINDASH_OIDC_CLIENT_SECRET` | — | `oidc`: the provider and the client (no secret for a public client) |
| `PAINDASH_OIDC_SCOPES`, `PAINDASH_OIDC_GROUPS_CLAIM` | `openid,email,profile`, `groups` | `oidc`: scopes requested; ID token claim holding the groups (`realm_access.roles` reaches into an object) |
| `PAINDASH_USERS_FILE` | — | `local`: the accounts, `name:bcrypt-hash[:group,…]` lines (`paindash hash-password`), read again when the file changes; `*` in front of a hash locks the account |
| `PAINDASH_SESSION_TTL` | `12h` | `oidc` and `local`: session lifetime |
| `PAINDASH_ALLOWED_GROUPS` | — | groups allowed in; empty allows any authenticated user |
| `PAINDASH_EDITOR_GROUPS` | — | groups that may record and revoke exceptions, the others read; empty: everyone allowed in |
| `PAINDASH_PULL_SECRET`, `PAINDASH_ECR_REGISTRIES` | — | registry credentials: a `.dockerconfigjson` path, ECR registries for the credential helper |
| `PAINDASH_GRYPE_DB_URL` | grype's | vulnerability database listing, e.g. a mirror for air-gapped clusters |
| `PAINDASH_REMATCH_INTERVAL` | `1h` | vulnerability database check (failed scans are retried every 6 h) |
| `PAINDASH_SCAN_CONCURRENCY` | `2` | images scanned in parallel |
| `PAINDASH_RETENTION` | `720h` | how long images that stopped running and old events are kept |
| `PAINDASH_ENRICH` | `on` | `off` disables KEV and EPSS (no egress to CISA and FIRST) |
| `PAINDASH_GITHUB_OWNERS` | — | fix prompts: GitHub owners whose images you build (`ghcr.io/<owner>/…`, also behind a pull-through cache) |
| `PAINDASH_GITOPS_REPO` | — | fix prompts: `owner/name` of the repo holding your manifests |
| `PAINDASH_DB_MAX_CONNS` | `4` | |
| `PAINDASH_SYNC_INTERVAL` | `30s` | inventory refresh |
| `PAINDASH_KEV_INTERVAL` | `1h` | CISA KEV refresh (EPSS is refreshed daily) |
| `PAINDASH_PROGRESS_INTERVAL` | `1m` | progress events while the first scan of a fresh install runs |
| `PAINDASH_LOG_LEVEL` | — | `debug` for verbose logs |
| `PAINDASH_SYFT`, `PAINDASH_GRYPE` | `syft`, `grype` | scanner binaries (from `PATH` by default) |
| `PAINDASH_LISTEN`, `PAINDASH_INTERNAL_LISTEN` | `:8080`, `:9090` | UI and API; `/metrics`, `/healthz`, `/readyz` |
| `PAINDASH_DEMO` | `false` | simulated clusters and scanner |

## Security

paindash reads cluster metadata through Prometheus and pulls images with the credentials you give
it; it never writes to a cluster or a registry. Its database holds the inventory and the
vulnerabilities of everything you run: treat it, and the UI, as sensitive.

Users sign in through [Pomerium](https://www.pomerium.com), whose signed assertion paindash
verifies (`PAINDASH_AUTH=pomerium`), with your OpenID Connect provider (`oidc`), or with local
accounts from a file of bcrypt hashes (`local`). Groups decide who gets in
(`PAINDASH_ALLOWED_GROUPS`) and who may record exceptions (`PAINDASH_EDITOR_GROUPS`, the others
are read-only). `PAINDASH_AUTH=disabled` serves anyone who reaches the port and records exceptions
as "anonymous": only for local use or behind an authenticating proxy you trust; the UI then shows a
"No auth" badge.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development

```sh
make demo      # database in docker compose, then the server in demo mode → http://localhost:8080
make test
paindash scan <repo@sha256:…>   # syft + grype on one image, to debug registry access
```

The UI is React + TypeScript + Tailwind (`web/`), embedded in the Go binary. syft and grype are
built from source, pinned to releases at least two weeks old (see [tools/README.md](tools/README.md)).
CI: every action and image pinned by digest; `go vet`, `go test -race`, govulncheck, `npm audit`,
gitleaks, Trivy, actionlint; the image is scanned before it is pushed, with SLSA provenance and an
SBOM. See [CONTRIBUTING.md](CONTRIBUTING.md); coding agents and new maintainers start with
[CLAUDE.md](CLAUDE.md).

## Roadmap

A Kubernetes API inventory source, Gateway API routes in the exposure and signed images come
next: see [ROADMAP.md](ROADMAP.md), and [docs/decisions.md](docs/decisions.md)
for why the current scope is what it is. Changes: [CHANGELOG.md](CHANGELOG.md).

paindash is maintained on a best-effort basis.

## License

[Apache-2.0](LICENSE)
