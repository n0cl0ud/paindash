# paindash documentation

paindash shows the vulnerabilities of what **actually runs** on your Kubernetes clusters, per
environment, in real time. It reads the image digests your kubelets pulled from kube-state-metrics,
through the Prometheus-compatible API you already have: no agent in the clusters, no access to the
Kubernetes API. It scans each digest once with syft and grype, stores the SBOM in PostgreSQL, and
rematches it whenever the vulnerability database changes, so new CVEs show up without a rescan or
a redeploy.

> [!TIP]
> To try it on a laptop, with simulated clusters and CVEs: `docker compose --profile demo up
> --build`, then open http://localhost:8080.

## Use

| Document | For |
|---|---|
| [**User guide**](guide.md) | Concepts, a tour of the UI, fix prompts, workflows, Prometheus metrics, API, FAQ |

## Run

| Document | For |
|---|---|
| [**Deploying paindash**](../deploy/README.md) | Prerequisites, Helm and kubectl installation, authentication, exposure, upgrades |
| [**Configuration**](configuration.md) | Every `PAINDASH_*` environment variable, its default and its Helm value |
| [**Security**](../SECURITY.md) | Trust model, reporting a vulnerability |

## Understand and contribute

| Document | For |
|---|---|
| [**How paindash works**](architecture.md) | Inventory, exposure, scanning, data model, caching, live feed, history, security model, limits |
| [**Design decisions**](decisions.md) | Why paindash is built the way it is, and what each choice implies |
| [**Roadmap**](../ROADMAP.md) | What is next, known issues and limits |
| [**Changelog**](../CHANGELOG.md) | What changed, release by release |
| [**Contributing**](../CONTRIBUTING.md) | Development setup, pull requests |
| [**Notes for maintainers**](../CLAUDE.md) | Commands, code layout, conventions and pitfalls (also read by coding agents) |
