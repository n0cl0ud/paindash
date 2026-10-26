# paindash: notes for coding agents and new maintainers

paindash is a real-time CVE dashboard of what actually runs on Kubernetes: it reads image digests
from kube-state-metrics through a Prometheus-compatible API, scans each digest once (syft SBOM,
stored), matches it with grype, rematches the SBOMs of running images when the vulnerability DB
changes, and serves a React UI, a live SSE feed and Prometheus metrics. Read [README.md](README.md)
first, then [docs/architecture.md](docs/architecture.md), [docs/decisions.md](docs/decisions.md)
(why things are the way they are) and [ROADMAP.md](ROADMAP.md) (what is next, known issues).

## Commands

```sh
make demo        # Postgres in docker compose + server in demo mode → http://localhost:8080
make test        # go vet + go test
make build       # web (npm ci + vite build) then the Go binary in bin/
cd web && npm run dev        # UI with hot reload, proxied to :8080
cd web && npm run typecheck
make snapshot PROMETHEUS_URL=http://localhost:9090   # inventory seen through Prometheus, no DB
paindash scan <repo@sha256:…>                         # syft + grype on one image
paindash hash-password                                # bcrypt hash for PAINDASH_USERS_FILE (local accounts)
docker compose --profile demo up --build              # the demo, fully in containers
helm lint deploy/helm/paindash --set database.url=postgres://u:p@db/x --set prometheus.url=http://p:9090 --set auth.mode=disabled
```

The Go binary embeds `web/dist` (`web/embed.go`): build the UI before `go build`, or the embed fails.

## Layout

| Path | What |
|---|---|
| `cmd/paindash` | entry point: configuration from `PAINDASH_*` env vars, wiring, `snapshot`, `scan` and `hash-password` subcommands |
| `internal/inventory` | `Source` interface; `Prometheus` reads kube-state-metrics series, attributes pods to workloads, derives exposure |
| `internal/pipeline` | `Syncer` (inventory every 30 s, events), `Worker` (scan queue, hourly DB check, rematch, retries), `Enricher` (KEV, EPSS) |
| `internal/scan` | syft/grype CLIs, SBOM pruning and match rules (`RulesVersion`), registry auth, OCI provenance labels |
| `internal/store` | PostgreSQL (pgx), embedded migrations `migrations/NNN_*.sql` run at startup; `Dataset` loads the read model |
| `internal/view` | pure read model: findings, summary, workloads, scope, promotion hints, image origin |
| `internal/api` | HTTP API, SSE stream, exceptions (OpenVEX), history, `/metrics` |
| `internal/demo` | simulated clusters, scanner and DB (`CVE-2099-*`), history backfill |
| `internal/auth` | who is calling: Pomerium JWT assertions, or paindash's own sessions (OpenID Connect, local accounts) and their `/auth/` pages |
| `web/src` | React 19 + TypeScript + Tailwind 4 + TanStack Query; `api/` (types mirror `internal/model`), `views/`, `components/`, `lib/` |
| `deploy/` | Helm chart, plain manifests, install guide |
| `tools/` | Go modules that pin syft and grype, built from source in the Dockerfile |

`web/src/api/types.ts` is the API contract: keep it in sync with `internal/model/model.go`.

## Conventions

- **English everywhere**: code, comments, UI, docs, commit messages.
- **Match the surrounding code**: comment density, naming, idioms. Comments explain why, briefly.
- **Commits**: one short line in the imperative ("Fix nav scrollbar"). No trailers (no Co-Authored-By).
- **Tests next to the code** (`*_test.go`, table-driven). The UI has no test runner: verify UI changes
  in the demo (and with headless Chrome screenshots, light and dark, desktop and 390 px wide).
- **Pin everything**: Go and npm versions, GitHub Actions by commit SHA, base images by digest.
  syft and grype only move to releases at least two weeks old (`tools/README.md`).
- **Never commit** credentials, internal hostnames, real cluster names or real scan results.
  Demo and test data use the fictitious `acme` org and `prod-1`-style cluster names.
- **Pragmatic first**: measure before optimizing; the simplest change that solves the problem; no
  speculative infrastructure.
- **UI quality matters**: consistent with the existing design tokens (`web/src/index.css`), light and
  dark themes, accessible (labels, keyboard), no layout shift; charts follow the same palette.

## Things that bite

- **Labels.** Envs and clusters come from series labels (`PAINDASH_ENV_LABEL`, default `env`;
  `PAINDASH_CLUSTER_LABEL`, default `cluster`). paindash's own metrics use `environment`, because
  Thanos external labels named `env` overwrite series labels.
- **Workload attribution** walks Pod → ReplicaSet → Deployment and Pod → Job → CronJob through
  owner series. When an owner series is missing (deleted before its pods, or not scraped yet) the
  owner is inferred from the controller-made name (`<deploy>-<pod-template-hash>`,
  `<cronjob>-<minutes>`); a standalone ReplicaSet stays one.
- **Findings are per env**: a finding merges every container of the env with that vuln and package.
  Workload pages request a workload-scoped view (`wl=ns/name`) so versions and locations are its own.
- **Promotion hints** are filtered server-side to earlier envs of `PAINDASH_PROMOTION`
  (`view.KeepPromotions`); the UI never re-filters.
- **Fixed versions**: show the lowest fix above the installed version of its release line
  (`web/src/lib/versions.ts`), never the first entry of `fixedIn`.
- **Counts are distinct vulns per env**: a KEV already present elsewhere in the env does not move
  the KEV tile when another workload gets it.
- **Exceptions** match vuln + package name (any version), optionally a namespace or workload, in
  every env. Their events go only to the envs where they cover a container.
- **History** points are written by the `/metrics` collection loop: coalesced over 5 min, after
  scans settle, at least daily. A change undone within 5 min never shows in history.
- **Filtered history** is recounted from `history_facts` by `view.CountFacts`: any counting change
  in `view.Summary` must be mirrored there. `TestCountFactsMatchesSummary` guards it.
- **Images that stop running** keep their SBOM for `PAINDASH_RETENTION` (instant re-analysis when
  they come back) but are not rematched meanwhile.
- **Scans**: a digest is scanned once; failures retry every 6 h; single-arch images are retried on
  the other platform. Changing pruning or matching rules: bump `scan.RulesVersion` (rematches all).
- **Session expiry**: API calls get a 401 (paindash's sessions) or a redirect/HTML page (Pomerium);
  the UI reloads itself once a minute at most, never while the exception form is open
  (`holdReload`). A JSON 403 is a read-only user (outside `PAINDASH_EDITOR_GROUPS`), not an ended
  session.
- **Single replica**: the scan queue, history writer and RWO grype cache assume one pod (Recreate).

## Before you open a PR

`make test`, `cd web && npm run build`, and for deploy changes `helm lint` + `kubeconform`. CI also
runs govulncheck, `npm audit`, gitleaks, Trivy and actionlint. Update `docs/` (variables:
`docs/configuration.md`, with `values.yaml`) when behavior or variables change, and `CHANGELOG.md`.
