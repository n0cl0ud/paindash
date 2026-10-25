# Configuration

paindash is configured with `PAINDASH_*` environment variables. The Helm chart sets them from its
values, shown under each variable; the few without a value go through `extraEnv`. Every value is
also documented in [`values.yaml`](../deploy/helm/paindash/values.yaml), and empty values keep the
defaults below.

> [!TIP]
> Only three things are required: a database, a Prometheus-compatible API, and the settings of
> one authentication mode. The chart refuses to render without them, and says what is missing.

**Contents:** [Database](#database) · [Inventory](#inventory) · [Exposure](#exposure) ·
[Scanning](#scanning) · [Enrichment](#enrichment) · [Authentication](#authentication) ·
[Fix prompts](#fix-prompts) · [Server](#server)

## Database

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_DATABASE_URL`<br><sub>`database.url`, or `database.existingSecret`</sub> | | PostgreSQL 14+, e.g. `postgres://paindash:…@db:5432/paindash?sslmode=require` |
| `PGHOST`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGSSLMODE`<br><sub>`extraEnv` or `envFrom`</sub> | | instead of the URL, the standard libpq variables |
| `PAINDASH_DB_MAX_CONNS`<br><sub>`database.maxConns`</sub> | `4` | connection pool size |

Migrations run at startup. paindash creates the key that seals its session cookies in its own
database (table `secrets`): nothing else to configure.

## Inventory

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_PROMETHEUS_URL`<br><sub>`prometheus.url`</sub> | | **required** (except in demo mode): a Prometheus-compatible API with the kube-state-metrics series; basic auth as `https://user:password@host` |
| `PAINDASH_PROMETHEUS_BEARER_TOKEN_FILE`<br><sub>`prometheus.bearerTokenFile`</sub> | | file holding a bearer token for that API, read at each sync |
| `PAINDASH_PROMETHEUS_CA_FILE`<br><sub>`prometheus.caFile`</sub> | | PEM certificates trusted for that API, on top of the system ones |
| `PAINDASH_PROMETHEUS_HEADERS`<br><sub>`prometheus.headers`</sub> | | `Name=value` headers, comma-separated, e.g. `X-Scope-OrgID=tenant-1` |
| `PAINDASH_ENV_LABEL`<br><sub>`prometheus.envLabel`</sub> | `env` | series label that tells environments apart |
| `PAINDASH_CLUSTER_LABEL`<br><sub>`prometheus.clusterLabel`</sub> | `cluster` | series label that tells clusters apart |
| `PAINDASH_DEFAULT_ENV`<br><sub>`prometheus.defaultEnv`</sub> | | env of the series without the env label (a single Prometheus); turns the env filter off |
| `PAINDASH_DEFAULT_CLUSTER`<br><sub>`prometheus.defaultCluster`</sub> | `default` | cluster of the series without the cluster label |
| `PAINDASH_ENVS`<br><sub>`envs`</sub> | `prod,test,dev` | environments shown, in switcher order; the first one is scanned first |
| `PAINDASH_PROMOTION`<br><sub>`promotion`</sub> | `dev,test,prod` | promotion chain: an image is only suggested from an earlier environment |
| `PAINDASH_SYNC_INTERVAL`<br><sub>`extraEnv`</sub> | `30s` | inventory refresh |

Credentials in `prometheus.url` would show in the pod spec: pass such a URL from a Secret through
`extraEnv` instead (see
[Authentication to the Prometheus API](../deploy/README.md#authentication-to-the-prometheus-api)).

## Exposure

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_PUBLIC_ENTRYPOINTS`<br><sub>`exposure.publicEntrypoints`</sub> | `web,websecure` | Traefik entrypoints reachable from the internet; `*-internal` and `*-int` are internal, any other is internet-facing (with a warning) |
| `PAINDASH_INGRESS_CLASSES`<br><sub>`exposure.ingressClasses`</sub> | | `class=internet` or `class=internal`, comma-separated; unlisted classes are internal when named `*internal*` or `*private*`, internet-facing otherwise |

How each workload gets its exposure:
[Exposure classification](../deploy/README.md#exposure-classification).

## Scanning

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_PULL_SECRET`<br><sub>`registry.pullSecret`</sub> | | a `.dockerconfigjson` file with the registry credentials (the chart mounts the Secret) |
| `PAINDASH_ECR_REGISTRIES`<br><sub>`registry.ecrRegistries`</sub> | | Amazon ECR registries pulled with the pod's IAM role, through the ECR credential helper |
| `PAINDASH_GRYPE_DB_URL`<br><sub>`scanner.grypeDbUrl`</sub> | grype's | vulnerability database listing, e.g. a mirror for air-gapped clusters |
| `PAINDASH_REMATCH_INTERVAL`<br><sub>`extraEnv`</sub> | `1h` | vulnerability database check; a new database rematches every running image |
| `PAINDASH_SCAN_CONCURRENCY`<br><sub>`scanner.concurrency`</sub> | `2` | images scanned in parallel |
| `PAINDASH_RETENTION`<br><sub>`retention`</sub> | `720h` | how long images that stopped running, and old events, are kept |
| `PAINDASH_PROGRESS_INTERVAL`<br><sub>`extraEnv`</sub> | `1m` | progress events while the first scan of a fresh install runs |
| `PAINDASH_SYFT`, `PAINDASH_GRYPE`<br><sub>`extraEnv`</sub> | `syft`, `grype` | scanner binaries, from `PATH` |

Failed scans are retried every 6 hours. An image published for a single platform is scanned for
that platform, so amd64 and arm64 nodes can be mixed.

## Enrichment

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_ENRICH`<br><sub>`enrichment.enabled`</sub> | `on` | `off` disables CISA KEV and FIRST EPSS, and their egress |
| `PAINDASH_KEV_INTERVAL`<br><sub>`extraEnv`</sub> | `1h` | CISA KEV refresh; EPSS is refreshed daily |

## Authentication

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_AUTH`<br><sub>`auth.mode`</sub> | `pomerium` | `pomerium`, `oidc`, `local` or `disabled` |
| `PAINDASH_POMERIUM_JWKS_URL`<br><sub>`auth.pomerium.jwksUrl`</sub> | | `pomerium` (required): the JWKS that signs the `X-Pomerium-Jwt-Assertion` header |
| `PAINDASH_POMERIUM_AUDIENCE`<br><sub>`auth.pomerium.audience`</sub> | | `pomerium` (required): the expected audience, the route host |
| `PAINDASH_POMERIUM_ISSUER`<br><sub>`auth.pomerium.issuer`</sub> | | `pomerium`: the expected issuer; empty skips the check |
| `PAINDASH_PUBLIC_URL`<br><sub>`auth.publicUrl`</sub> | | `oidc` and `local` (required): the URL browsers use (redirect URI, cookies, origin of the sign-in form); https, plain http only on localhost |
| `PAINDASH_OIDC_ISSUER`<br><sub>`auth.oidc.issuer`</sub> | | `oidc` (required): the provider |
| `PAINDASH_OIDC_CLIENT_ID`<br><sub>`auth.oidc.clientId`</sub> | | `oidc` (required): the client |
| `PAINDASH_OIDC_CLIENT_SECRET`<br><sub>`auth.oidc.existingSecret`</sub> | | `oidc`: the client secret; none for a public client (PKCE only) |
| `PAINDASH_OIDC_SCOPES`<br><sub>`auth.oidc.scopes`</sub> | `openid,email,profile` | `oidc`: scopes requested |
| `PAINDASH_OIDC_GROUPS_CLAIM`<br><sub>`auth.oidc.groupsClaim`</sub> | `groups` | `oidc`: ID token claim holding the groups; a dotted path such as `realm_access.roles` reaches into objects |
| `PAINDASH_USERS_FILE`<br><sub>`auth.local.existingSecret`</sub> | | `local` (required): the accounts, `name:bcrypt-hash[:group,…]` lines (`paindash hash-password`), read again when the file changes; `*` in front of a hash locks the account |
| `PAINDASH_SESSION_TTL`<br><sub>`auth.sessionTtl`</sub> | `12h` | `oidc` and `local`: session lifetime |
| `PAINDASH_ALLOWED_GROUPS`<br><sub>`auth.allowedGroups`</sub> | | groups allowed in; empty allows any authenticated user |
| `PAINDASH_EDITOR_GROUPS`<br><sub>`auth.editorGroups`</sub> | | groups that may record and revoke exceptions, the others are read-only; empty: everyone allowed in |

Each mode, with examples: [Authentication](../deploy/README.md#authentication).

> [!WARNING]
> `PAINDASH_AUTH=disabled` serves anyone who reaches port 8080 and records exceptions as
> "anonymous". Use it only for local use, or behind an authenticating proxy that is the only way
> in.

## Fix prompts

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_GITHUB_OWNERS`<br><sub>`fixPrompt.githubOwners`</sub> | | GitHub owners whose images you build (`ghcr.io/<owner>/…`, also behind a pull-through cache): fixed in their source repo |
| `PAINDASH_GITOPS_REPO`<br><sub>`fixPrompt.gitopsRepo`</sub> | | `owner/name` of the repository holding your manifests, where third-party images are bumped |

## Server

| Variable <sub>Helm value</sub> | Default | |
|---|---|---|
| `PAINDASH_LISTEN`<br><sub>not set by the chart (port 8080)</sub> | `:8080` | UI and API |
| `PAINDASH_INTERNAL_LISTEN`<br><sub>not set by the chart (port 9090)</sub> | `:9090` | `/metrics`, `/healthz` and `/readyz`, without authentication: never route it |
| `PAINDASH_LOG_LEVEL`<br><sub>`extraEnv`</sub> | | `debug` for verbose logs |
| `PAINDASH_DEMO`<br><sub>`demo.enabled`</sub> | `false` | simulated clusters, scanner and vulnerability database (`CVE-2099-*`); still needs PostgreSQL |
