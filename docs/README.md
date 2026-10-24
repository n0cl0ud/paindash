# paindash documentation

paindash shows the vulnerabilities of what **actually runs** on your Kubernetes clusters, per
environment, in real time. It reads the image digests your kubelets pulled from kube-state-metrics,
through the Prometheus-compatible API you already have (no agent in the clusters, no Kubernetes API
access), scans each digest once with syft and grype, stores the SBOM in PostgreSQL, and rematches
every stored SBOM whenever the vulnerability database changes, so new CVEs show up without a rescan
or a redeploy. Findings are sorted by urgency (CISA KEV, severity, exposure, EPSS), with the fixed
version of the release line you run, "already fixed in test, promote" hints, expiring OpenVEX
exceptions, history, Prometheus metrics and fix prompts for coding agents. To try it on a laptop,
with simulated clusters and CVEs: `docker compose --profile demo up --build`, then open
http://localhost:8080.

| Document | For |
|---|---|
| [Using paindash](guide.md) | Concepts, a tour of the UI, fix prompts, workflows, Prometheus metrics, API, FAQ |
| [How paindash works](architecture.md) | Inventory, exposure, scanning, data model, caching, live feed, history, security model, limits |
| [Deploying paindash](../deploy/README.md) | Prerequisites, Helm and kubectl installation, authentication, upgrades |
| [Configuration](../README.md#configuration) | The `PAINDASH_*` environment variables |
| [Design decisions](decisions.md) | Why paindash is built the way it is, and what each choice implies |
| [Roadmap](../ROADMAP.md) | What is next, known issues and limits |
| [Notes for maintainers](../CLAUDE.md) | Commands, code layout, conventions and pitfalls (also read by coding agents) |
| [Security](../SECURITY.md) | Trust model, reporting a vulnerability |
| [Contributing](../CONTRIBUTING.md) | Development setup, pull requests |
