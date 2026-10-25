# Security

## Reporting a vulnerability

Please report vulnerabilities privately, through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security tab → "Report a vulnerability"). Do not open a public issue.

You will get an answer within a week. Fixes are released as a new version, with an advisory once
users have had time to upgrade.

## Supported versions

The latest release.

## Trust model

- **Cluster metadata, read-only.** paindash queries a Prometheus-compatible API for
  kube-state-metrics series. It has no Kubernetes API access (its ServiceAccount token is not even
  mounted).
- **Registry credentials.** syft pulls the images that run to build their SBOM, with the pull
  secret (and, on AWS, the ECR credential helper) you configure. They are never logged.
- **Outbound.** The vulnerability database (grype, configurable mirror), CISA KEV and FIRST EPSS
  (`PAINDASH_ENRICH=off` disables the last two).
- **Writes.** Only to its own PostgreSQL database. It never writes to a cluster, a registry or a
  repository. Fix prompts are text for you to paste into a coding agent; paindash runs nothing.
- **Sensitive data.** The database and the UI list everything you run and its vulnerabilities:
  restrict access to both.
- **Authentication.** Pomerium's signed assertion, OpenID Connect, or local accounts (bcrypt hashes,
  rate-limited sign-in), with encrypted session cookies for the last two; editor groups limit who
  records exceptions. `PAINDASH_AUTH=disabled` is for local use or a trusted authenticating proxy
  only.
- **Internal port.** `/metrics`, `/healthz` and `/readyz` are served on port 9090 without
  authentication: never route it.
- **Supply chain.** syft and grype are built from pinned sources; every base image and CI action is
  pinned by digest; images are scanned before they are pushed and carry SLSA provenance and an
  SBOM.
- **Runtime image.** Chainguard static (Wolfi): no shell, no package manager, no libc, a CA bundle
  that follows Mozilla's. It runs as UID 10001 with a read-only root filesystem (chart and
  manifests); to look inside the pod, attach an ephemeral container with `kubectl debug`.
