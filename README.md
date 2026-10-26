<div align="center">

<img src="web/public/favicon.svg" alt="" width="76" height="76">

# paindash

**The CVEs of what actually runs on your Kubernetes clusters.**<br>
Per environment, in real time, sorted by what to fix first.

[![Build](https://github.com/n0cl0ud/paindash/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/n0cl0ud/paindash/actions/workflows/docker.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go 1.27](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)](go.mod)
[![Helm chart](https://img.shields.io/badge/Helm-chart-0F1689?logo=helm&logoColor=white)](deploy/README.md)
![Image for amd64 and arm64](https://img.shields.io/badge/image-amd64%20%7C%20arm64-2496ED?logo=docker&logoColor=white)

[**Try it**](#try-it-in-one-command) · [**Features**](#what-you-get) · [**Install**](#install) ·
[**Docs**](docs/README.md) · [**Roadmap**](ROADMAP.md)

</div>

<br>

![To fix in prod: the actively exploited vulnerability first, already fixed in dev and test, with the history of the environment and the live feed](docs/screenshots/todo.png)

paindash reads the image digests your kubelets actually pulled, from the kube-state-metrics series
you already collect. It scans each image once with [syft](https://github.com/anchore/syft) and
[grype](https://github.com/anchore/grype), keeps the SBOM, and rematches it whenever the
vulnerability database changes. A new CVE shows up within the hour, with no rescan and no
redeploy.

## Why paindash

- **What runs, nothing else.** The digest each kubelet pulled, not the tag or what git says. An
  image promoted from test to prod is scanned once.
- **New CVEs without a rescan.** SBOMs are stored and rematched when the vulnerability database
  changes (checked hourly). A deployment shows up in about 30 seconds.
- **What to fix first.** Actively exploited (CISA KEV) first, then severity, exposure and EPSS,
  with the fixed version of the release line you run and "already fixed in test, promote" hints.
- **Nothing to install in your clusters.** No agent, no operator, no CRD, no access to the
  Kubernetes API: paindash reads the metrics you already have.

## Try it in one command

The demo simulates four clusters, a scanner and a vulnerability database (`CVE-2099-*`): releases
land in dev, get promoted to test then prod, and new CVEs come out every two minutes.

```sh
docker compose --profile demo up --build
```

Then open http://localhost:8080.

## What you get

**Know what to fix first**

- Findings sorted by urgency: actively exploited (CISA KEV), severity, exposure, EPSS.
- The fixed version of the release line you run, not the first one of the advisory.
- "Already fixed in test, promote" hints along your promotion chain (dev → test → prod).
- The exposure of each workload (internet-facing, internal or not exposed), from Ingresses,
  LoadBalancer Services and Traefik IngressRoutes.

**Stay on top of it**

- A live feed of deployments, new CVEs and additions to the KEV catalog.
- History per environment (actively exploited, critical with a fix, high with a fix on
  internet-facing workloads, excepted), with what moved each curve, also recounted for any
  namespace, component or exposure filter.
- Prometheus metrics per environment and workload, for your alerts.
- Scopes by namespace, component and exposure, kept in the URL: every view is a link to share.

**Get it fixed**

- **Fix prompts** *(experimental)*: per workload or vulnerability, a Markdown prompt for Claude
  Code or any coding agent, to fix and open the pull requests, one per repository. Your own images
  are fixed in their source repository (from their OCI `source` and `revision` labels),
  third-party ones bumped in your manifests, or pinned to the image already fixed in an earlier
  environment.
- **Exceptions as OpenVEX**: "not affected" statements with a justification, a scope and a
  mandatory expiry, exported as an OpenVEX document for auditors.

**Fit your setup**

- Sign in through Pomerium, your OpenID Connect provider or local accounts; read-only users.
- Several clusters and environments in one instance, told apart by series labels.
- A Helm chart and plain manifests; amd64 and arm64 images with SLSA provenance and an SBOM.

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/workloads.png" alt="The workloads of prod, with their vulnerabilities, exposure and KEV count"></td>
    <td width="50%"><img src="docs/screenshots/workload.png" alt="A workload: its image and source commit, and its vulnerabilities, already fixed in dev and test"></td>
  </tr>
  <tr>
    <td align="center"><sub>Every workload, by severity, exposure and KEV</sub></td>
    <td align="center"><sub>A workload, its source commit and what to promote</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="docs/screenshots/finding.png" alt="A vulnerability: the fix already deployed in dev and test, CVSS, EPSS and the affected package"></td>
    <td width="50%"><img src="docs/screenshots/fix-prompt.png" alt="A fix prompt for a coding agent, with the data of the workload"></td>
  </tr>
  <tr>
    <td align="center"><sub>A vulnerability, and where it is already fixed</sub></td>
    <td align="center"><sub>A fix prompt, ready for your coding agent</sub></td>
  </tr>
</table>

### Why not Trivy Operator or Kubescape?

They scan from inside each cluster and report per resource. paindash is a single view across
clusters and environments, built on the metrics you already collect: no agent or operator in the
clusters, a promotion view ("fixed in test, not in prod yet"), continuous rematching of stored
SBOMs instead of rescans, history, expiring exceptions, and prompts to get the fixes done.

## How it works

![How paindash works: kube-state-metrics through Prometheus, inventory, syft, grype, enrichment, read model, outputs](docs/architecture.svg)

1. **Inventory.** Every 30 seconds, paindash reads the running containers and their image digests
   from kube-state-metrics, through your Prometheus, and attributes them to workloads and
   environments.
2. **Scan once.** Each new digest gets an SBOM from syft, stored in PostgreSQL.
3. **Match again and again.** grype matches the SBOMs of running images, and matches them all
   again when its vulnerability database changes.
4. **Rank.** CISA KEV, FIRST EPSS and the exposure of each workload sort the findings by urgency.
5. **Serve.** A web UI, a live feed, Prometheus metrics and an OpenVEX export.

The details, from data model to security model: [How paindash works](docs/architecture.md).

## Install

> [!IMPORTANT]
> **Prerequisites:** kube-state-metrics 2.6.0 or later, scraped with `honor_labels: true`
> (kube-prometheus-stack does both); a Prometheus-compatible API holding its series (Prometheus,
> Thanos, Mimir, VictoriaMetrics...); PostgreSQL 14 or later. paindash needs no access to the
> Kubernetes API. Details: [Prerequisites](deploy/README.md#prerequisites).

**1. See what paindash will see.** A one-off pod prints the inventory it reads from your
Prometheus (or why it cannot):

```sh
kubectl run paindash-snapshot --restart=Never --image=ghcr.io/n0cl0ud/paindash:0.1.2 \
  --env=PAINDASH_PROMETHEUS_URL=http://prometheus-operated.monitoring.svc:9090 -- snapshot
kubectl wait pod/paindash-snapshot --timeout=2m \
  --for=jsonpath='{.status.containerStatuses[0].state.terminated}'
kubectl logs paindash-snapshot; kubectl delete pod paindash-snapshot
```

Add `--env=PAINDASH_ENVS=prod,staging,dev` when your environments are not prod, test and dev, and
`--env=PAINDASH_DEFAULT_ENV=prod` when the series carry no `env` label (a single Prometheus).

**2. Write your values**, here with your OpenID Connect provider:

```yaml
prometheus:
  url: http://prometheus-operated.monitoring.svc:9090
envs: [prod, test, dev]                # your environments, in switcher order
database:
  existingSecret: paindash-db          # key "url": postgres://paindash:...@db:5432/paindash
auth:
  mode: oidc                           # or pomerium, local, disabled
  publicUrl: https://paindash.example.com
  oidc:
    issuer: https://sso.example.com/realms/main
    clientId: paindash                 # redirect URI: <publicUrl>/auth/callback
    existingSecret: paindash-oidc      # key "client-secret"
  editorGroups: [security]             # may record exceptions; the others read
```

**3. Install the chart**, from a clone of this repository:

```sh
kubectl create namespace paindash
kubectl -n paindash create secret generic paindash-db \
  --from-literal=url="$DATABASE_URL"
kubectl -n paindash create secret generic paindash-oidc \
  --from-literal=client-secret="$CLIENT_SECRET"
helm install paindash deploy/helm/paindash -n paindash -f values.yaml
```

Route your public URL to the `paindash` Service, port 8080 (`ingress.enabled` creates an
Ingress). Port 9090 serves `/metrics` without authentication: keep it internal.

Local accounts, Pomerium, private registries, plain manifests and upgrades:
[Deploying paindash](deploy/README.md). Every variable and its Helm value:
[Configuration](docs/configuration.md).

## Security

paindash reads cluster metadata through Prometheus and pulls images with the credentials you give
it; it never writes to a cluster or a registry. Its database and its UI list everything you run
and its vulnerabilities: treat both as sensitive. Groups decide who gets in and who may record
exceptions; everyone else is read-only.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Documentation

| Document | For |
|---|---|
| [**User guide**](docs/guide.md) | Concepts, a tour of the UI, fix prompts, workflows, metrics, API, FAQ |
| [**Deploying paindash**](deploy/README.md) | Prerequisites, Helm and kubectl, authentication, exposure, upgrades |
| [**Configuration**](docs/configuration.md) | Every `PAINDASH_*` variable, its default and its Helm value |
| [**How paindash works**](docs/architecture.md) | Inventory, scanning, data model, live feed, history, security model, limits |
| [**Design decisions**](docs/decisions.md) | Why paindash is built the way it is, and what each choice implies |
| [**Roadmap**](ROADMAP.md) · [**Changelog**](CHANGELOG.md) | What is next and the known limits; what changed |

## Contributing

```sh
make demo                # demo mode on http://localhost:8080, database in docker compose
make test                # go vet + go test
cd web && npm run dev    # UI with hot reload
```

The UI is React, TypeScript and Tailwind, embedded in the Go binary. syft and grype are built from
source, pinned to releases at least two weeks old. CI pins every action and image by digest and
runs `go vet`, `go test -race`, govulncheck, `npm audit`, gitleaks, Trivy and actionlint; images
are scanned before they are pushed. See [CONTRIBUTING.md](CONTRIBUTING.md); coding agents and new
maintainers start with [CLAUDE.md](CLAUDE.md).

Next on the [roadmap](ROADMAP.md): a Kubernetes API inventory source, Gateway API routes in the
exposure, passkeys for local accounts, and signed images. paindash is maintained on a best-effort
basis.

## License

[Apache-2.0](LICENSE)
