# Scanners built from source

syft and grype are built in the Dockerfile from these modules instead of their release
binaries. That way we can:

- keep versions released at least two weeks ago;
- compile them with our Go toolchain (stdlib fixes);
- override vulnerable dependencies.

Each module pins its scanner with a `tool` directive. Only these dependencies differ from
upstream:

| Module | Override | Why |
|---|---|---|
| `golang.org/x/net` | v0.59.0 → v0.60.0 | CVE-2026-78669 (HTTP/2) |
| `github.com/gabriel-vasile/mimetype` | v1.4.15 → v1.4.16 | v1.4.15 retracted: quadratic time on crafted CDF files |

Dependabot (gomod, `/tools/syft` and `/tools/grype`) proposes the bumps. To check a
binary: `govulncheck -mode=binary <binary>`.
