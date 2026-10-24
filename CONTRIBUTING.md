# Contributing

Issues and pull requests are welcome. For anything larger than a fix, open an issue first so we can
agree on the approach.

## Development

Go (see `go.mod`), Node 24, Docker.

```sh
make demo   # the database in docker compose, then the server in demo mode → http://localhost:8080
make test   # go vet + go test
cd web && npm run dev   # UI with hot reload, proxied to the server on :8080
```

`make snapshot PROMETHEUS_URL=…` prints the inventory paindash sees, without a database.

## Pull requests

- Keep them focused: one change, with its tests.
- `make test` and `cd web && npm run build` must pass; CI also runs govulncheck, `npm audit`,
  gitleaks, Trivy and actionlint.
- Commit messages: one short line in the imperative.
- New dependencies, CI actions and base images are pinned (versions, SHAs, digests). syft and grype
  only move to releases at least two weeks old (see `tools/README.md`).
- Never commit credentials, internal hostnames or real scan results.

By contributing, you agree that your contributions are licensed under the [Apache-2.0](LICENSE)
license.
