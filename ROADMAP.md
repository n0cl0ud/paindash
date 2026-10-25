# Roadmap

What is next, roughly in priority order, and the known issues. Decisions behind the current scope:
[docs/decisions.md](docs/decisions.md).

## Next

- **Kubernetes API inventory source**, for clusters without Prometheus: in-cluster, one cluster per
  instance, env set by configuration (the `inventory.Source` interface is ready).
- **Gateway API** `HTTPRoute` in the exposure model.
- **Signed assertions of other identity-aware proxies** (Cloudflare Access, Google IAP), checked
  like Pomerium's. Trusting plain identity headers (oauth2-proxy) only after a threat model.
- **Signed images** (cosign keyless) on top of the SLSA provenance and SBOM already attached.
- **Alerting**: ship example PrometheusRules for the `/metrics` series (new KEV on an
  internet-facing workload, stale vulnerability DB, stale inventory).
- **Dependabot alerts ingestion**, to cross-check source-level alerts with what runs.
- **CVE delta on GitOps pull requests**: comment the vulnerabilities an image bump adds or removes.

## Known issues and limits

- **Single replica only** (scan queue, history writer and grype cache assume one pod).
- **History is written by the `/metrics` collection loop**: it works because the loop always runs,
  but the two concerns are coupled.
- **Stopped images are not rematched**: if a digest comes back within the retention period, its
  findings date from the last DB it was matched against until the next DB update.
- **Exceptions match by package name** in any version and every env: precise enough for VEX
  "not affected" statements, but broad.
- **IRSA with `automountServiceAccountToken: false`**: the EKS webhook projects its own token, so
  ECR pulls should work, but this has not been tested yet with the chart.
- **OpenVEX products** are generic purls (`pkg:generic/<name>`), as exceptions are not tied to an
  ecosystem.

## Maintenance

- **syft and grype**: bump only to releases at least two weeks old (`tools/README.md`); Dependabot
  opens the PRs.
- **Node**: the build image follows the active LTS; move `node` and `@types/node` majors by hand when
  the next LTS lands (Dependabot ignores their majors).
- **grype's Go dependencies**: some advisories (e.g. on `github.com/docker/docker`) have no fixed
  version under that module path; check reachability with `govulncheck -mode=binary` on the built
  grype before dismissing them.
