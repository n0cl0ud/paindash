# Deploying paindash

paindash runs as a single pod. It reads the kube-state-metrics series of your clusters through a
Prometheus-compatible API, scans each running image digest with syft and grype, and stores the
results in PostgreSQL. It never calls the Kubernetes API: no RBAC, no ServiceAccount token.

- [`helm/paindash`](helm/paindash): the Helm chart.
- [`kubernetes/paindash.yaml`](kubernetes/paindash.yaml): the same defaults as plain manifests.

## Prerequisites

**Kubernetes.** One pod: 250m CPU and 512Mi requested, up to 4Gi of memory; a 10Gi
ReadWriteOnce volume for the grype DB (~3 GB); up to 10Gi of node ephemeral storage, where syft
unpacks image layers.

**kube-state-metrics and a Prometheus-compatible query API.** Every cluster to inventory runs
kube-state-metrics, and its series are queryable through one `/api/v1/query` endpoint (Prometheus,
Thanos Query, Mimir, VictoriaMetrics...). paindash reads `kube_pod_container_info`,
`kube_pod_init_container_info`, `kube_pod_owner`, `kube_replicaset_owner`, `kube_job_owner`, and
for exposure `kube_service_status_load_balancer_ingress`, `kube_ingress_info`, `kube_ingress_path`,
the optional `kube_traefik_*` series below, and `kube_endpointslice_endpoints` or
`kube_endpoint_address` with `kube_pod_info` to find the pods behind each Service.

- **Several clusters:** the series must carry an env label and a cluster label (default `env` and
  `cluster`, set with `prometheus.envLabel` / `prometheus.clusterLabel`). They are usually external
  labels set per cluster and kept by Thanos, Mimir, or a Grafana Agent / Alloy remote write. Only
  series whose env is in `envs` are read.
- **One Prometheus without such labels:** set `prometheus.defaultEnv` (and optionally
  `prometheus.defaultCluster`): series without the env label get that env, and the env filter
  is off.

kube-state-metrics v2.6.0 or later, scraped with `honor_labels: true` so that its series keep their
own `namespace`, `pod` and `container` labels. kube-prometheus-stack and kube-prometheus set it; the
standalone `kube-state-metrics` chart does not (`prometheus.monitor.http.honorLabels: true`).
Without it, Prometheus renames them `exported_*`, and paindash attributes containers to the
kube-state-metrics pod and loses the exposure. Check:
`kube_pod_container_info{exported_namespace!=""}` must return nothing.

Google Cloud Managed Service for Prometheus is not supported yet: its kube-state-metrics example
keeps only part of these series, and its documentation says that it renames a scraped `namespace`
label `exported_namespace`.

**Authentication to the Prometheus API**, when it asks for one:

- **Basic auth:** credentials in the URL (`https://user:password@host`). Pass such a URL from a
  Secret rather than `prometheus.url`, which would show it in the pod spec:

  ```yaml
  extraEnv:
  - name: PAINDASH_PROMETHEUS_URL
    valueFrom:
      secretKeyRef: {name: paindash-prometheus, key: url}
  ```

- **Bearer token:** `prometheus.bearerTokenFile`, a file read at each sync, so that a rotated token
  (a projected ServiceAccount token) is picked up.
- **Private CA:** `prometheus.caFile`, PEM certificates trusted for this API only, on top of the
  system ones.
- **Headers:** `prometheus.headers`, e.g. `X-Scope-OrgID: tenant-1` for a multi-tenant Mimir.

Mount the token and CA files with `extraVolumes` and `extraVolumeMounts`. OpenShift's Thanos
Querier, for example, takes the pod's ServiceAccount token once that ServiceAccount is bound to the
`cluster-monitoring-view` ClusterRole, and its certificate is signed by the service CA, published in
every namespace as the `openshift-service-ca.crt` ConfigMap:

```sh
kubectl create clusterrolebinding paindash-monitoring-view \
  --clusterrole=cluster-monitoring-view --serviceaccount=paindash:paindash
```

```yaml
prometheus:
  url: https://thanos-querier.openshift-monitoring.svc:9091
  bearerTokenFile: /var/run/secrets/paindash/token
  caFile: /var/run/secrets/paindash/service-ca.crt
extraVolumes:
- name: prometheus-auth
  projected:
    sources:
    - serviceAccountToken: {path: token, expirationSeconds: 3600}
    - configMap:
        name: openshift-service-ca.crt
        items: [{key: service-ca.crt, path: service-ca.crt}]
extraVolumeMounts:
- {name: prometheus-auth, mountPath: /var/run/secrets/paindash, readOnly: true}
```

**OpenShift.** The `restricted-v2` SCC assigns the user and the fsGroup from the namespace's ranges
and rejects the chart's fixed 10001: set `podSecurityContext.runAsUser`, `runAsGroup` and `fsGroup`
to `null`. paindash runs under any UID.

**PostgreSQL 14+.** Not bundled. paindash creates and migrates its own schema in a database it
owns:

```sql
CREATE ROLE paindash LOGIN PASSWORD '...';
-- Managed PostgreSQL (RDS, Cloud SQL...) without superuser: GRANT paindash TO CURRENT_USER;
CREATE DATABASE paindash OWNER paindash;
```

The pool holds up to `database.maxConns` connections (default 4).

**Registry credentials for private images.** syft pulls every running image by digest. Public
images need nothing. For private ones, create a `kubernetes.io/dockerconfigjson` Secret with
read-only credentials in the paindash namespace and set `registry.pullSecret`:

```sh
kubectl -n paindash create secret docker-registry regcred \
  --docker-server=ghcr.io --docker-username=USER --docker-password="$READ_ONLY_TOKEN"
```

For Amazon ECR, list the registries in `registry.ecrRegistries` and give the pod an IAM role
allowed to pull (`ecr:GetAuthorizationToken`, `ecr:BatchGetImage`,
`ecr:GetDownloadUrlForLayer`), e.g. IRSA through
`serviceAccount.annotations.eks\.amazonaws\.com/role-arn`.

**Exposure data.** Ingresses and LoadBalancer Services need nothing beyond the default
kube-state-metrics series: EndpointSlices (a default resource since v2.18.0) or Endpoints (the
default before) lead from each Service to its pods. Traefik IngressRoutes need its custom resource
state config. With the `prometheus-community/kube-state-metrics` chart (under
`kube-state-metrics:` in kube-prometheus-stack):

```yaml
rbac:
  extraRules:
  - apiGroups: [traefik.io]
    resources: [ingressroutes, ingressroutetcps, ingressrouteudps]
    verbs: [list, watch]
customResourceState:
  enabled: true
  config:
    spec:
      resources:
      # kube_traefik_ingressroute_entrypoint{namespace,ingressroute,entrypoint}
      # kube_traefik_ingressroute_service{namespace,ingressroute,service,service_namespace,service_kind}
      - groupVersionKind: {group: traefik.io, version: v1alpha1, kind: IngressRoute}
        metricNamePrefix: kube_traefik_ingressroute
        labelsFromPath:
          namespace: [metadata, namespace]
          ingressroute: [metadata, name]
        metrics:
        - name: entrypoint
          help: Entrypoints an IngressRoute is attached to.
          each:
            type: Info
            info:
              path: [spec, entryPoints]
              labelsFromPath:
                entrypoint: []
        - name: service
          help: First Service of each route of an IngressRoute.
          each:
            type: Info
            info:
              path: [spec, routes]
              labelsFromPath:
                service: [services, "0", name]
                service_namespace: [services, "0", namespace]
                service_kind: [services, "0", kind]
      # kube_traefik_ingressroutetcp_entrypoint / _service
      - groupVersionKind: {group: traefik.io, version: v1alpha1, kind: IngressRouteTCP}
        metricNamePrefix: kube_traefik_ingressroutetcp
        labelsFromPath:
          namespace: [metadata, namespace]
          ingressroute: [metadata, name]
        metrics:
        - name: entrypoint
          help: Entrypoints an IngressRouteTCP is attached to.
          each:
            type: Info
            info:
              path: [spec, entryPoints]
              labelsFromPath:
                entrypoint: []
        - name: service
          help: First Service of each route of an IngressRouteTCP.
          each:
            type: Info
            info:
              path: [spec, routes]
              labelsFromPath:
                service: [services, "0", name]
                service_namespace: [services, "0", namespace]
      # kube_traefik_ingressrouteudp_entrypoint / _service
      - groupVersionKind: {group: traefik.io, version: v1alpha1, kind: IngressRouteUDP}
        metricNamePrefix: kube_traefik_ingressrouteudp
        labelsFromPath:
          namespace: [metadata, namespace]
          ingressroute: [metadata, name]
        metrics:
        - name: entrypoint
          help: Entrypoints an IngressRouteUDP is attached to.
          each:
            type: Info
            info:
              path: [spec, entryPoints]
              labelsFromPath:
                entrypoint: []
        - name: service
          help: First Service of each route of an IngressRouteUDP.
          each:
            type: Info
            info:
              path: [spec, routes]
              labelsFromPath:
                service: [services, "0", name]
                service_namespace: [services, "0", namespace]
```

A standalone kube-state-metrics takes the same `spec` in the file given to
`--custom-resource-state-config-file` (with `kind: CustomResourceStateMetrics`); its ClusterRole
needs the rule above plus list/watch on `customresourcedefinitions` (`apiextensions.k8s.io`). Only
the first Service of each route is exported; a missing `service_kind` means `Service`. Traefik
before v2.10 uses the `traefik.containo.us` group.

**Network egress**, if restricted: the Prometheus API, PostgreSQL, the registries of the scanned
images (and their blob storage), the grype DB (`grype.anchore.io`, or `scanner.grypeDbUrl`), the
Pomerium JWKS or the OpenID Connect provider, and, unless `enrichment.enabled=false`,
`www.cisa.gov` (KEV) and `api.first.org` (EPSS).

## Install with Helm

From a clone of the repository:

```sh
kubectl create namespace paindash
kubectl -n paindash create secret generic paindash-db --from-literal=url="$DATABASE_URL"
helm install paindash deploy/helm/paindash -n paindash -f values.yaml
```

Example `values.yaml`, several clusters behind Thanos:

```yaml
prometheus:
  url: http://thanos-query.monitoring.svc:9090
envs: [prod, staging, dev]           # switch order; the first is scanned first
promotion: [dev, staging, prod]      # order fixes travel through the envs
database:
  existingSecret: paindash-db        # key "url": postgres://paindash:...@host:5432/paindash?sslmode=require
auth:
  pomerium:
    jwksUrl: https://authenticate.example.com/.well-known/pomerium/jwks.json
    audience: paindash.example.com
registry:
  pullSecret: regcred
exposure:
  publicEntrypoints: [web, websecure]
  ingressClasses: {nginx: internet, nginx-internal: internal}
fixPrompt:
  githubOwners: [acme]               # images built from these owners' repositories
  gitopsRepo: acme/gitops            # where third-party images are bumped
serviceMonitor:
  enabled: true
```

One Prometheus, no env or cluster labels:

```yaml
prometheus:
  url: http://prometheus-operated.monitoring.svc:9090
  defaultEnv: prod
  defaultCluster: main
envs: [prod]
```

Every value is documented in [`values.yaml`](helm/paindash/values.yaml); empty values leave the
binary's defaults. Rendering fails without a database (`database.url`, `database.existingSecret`,
or `PG*` variables through `extraEnv`/`envFrom`) or without `prometheus.url`.

**Demo.** `demo.enabled=true` simulates clusters and a scanner with fake CVEs (`CVE-2099-*`); it
needs no Prometheus but still needs PostgreSQL. It does not change authentication: set
`auth.mode=disabled` too to try it through `kubectl port-forward`.

## Install with kubectl

[`kubernetes/paindash.yaml`](kubernetes/paindash.yaml) holds the Namespace, ServiceAccount, cache
PersistentVolumeClaim, Deployment and Service. Replace the placeholders (`PROMETHEUS_URL`,
`POMERIUM_JWKS_URL`, `POMERIUM_AUDIENCE`) and review the lines marked `EDIT`, then:

```sh
kubectl apply -f deploy/kubernetes/paindash.yaml
kubectl -n paindash create secret generic paindash-db --from-literal=url="$DATABASE_URL"
```

The pod starts once the `paindash-db` Secret exists. Other settings are `PAINDASH_*` environment
variables, listed in the project README.

## Authentication

Four modes (`auth.mode`): Pomerium, OpenID Connect, local accounts, or disabled. In every mode,
groups decide who gets in (`auth.allowedGroups`, empty: any authenticated user) and who may record
and revoke exceptions (`auth.editorGroups`, empty: everyone allowed in; the others read
everything, marked "Read-only").

**Pomerium.** Pomerium enforces the access policy; paindash verifies the signed
`X-Pomerium-Jwt-Assertion` header on every request, so a request that bypasses Pomerium
(port-forward, another pod) is rejected. Exceptions are recorded under the user's email.

Pomerium route:

```yaml
- from: https://paindash.example.com
  to: http://paindash.paindash.svc.cluster.local:8080
  pass_identity_headers: true
  timeout: 0s                     # /api/stream (Server-Sent Events) stays open
  policy:
    allow:
      or:
      - claim/groups: GROUP_ID
```

paindash values:

```yaml
auth:
  mode: pomerium
  pomerium:
    jwksUrl: https://authenticate.example.com/.well-known/pomerium/jwks.json
    audience: paindash.example.com   # the route host
    issuer: ""                       # optional: empty skips the issuer check
  allowedGroups: []                  # optional app-side check on the "groups" claim
```

**OpenID Connect (`oidc`).** paindash signs users in with your identity provider (Keycloak, Dex,
Entra ID, Okta, Google, Authentik...), authorization code flow with PKCE, then keeps them in a
session of its own. Register a client with the redirect URI `<publicUrl>/auth/callback`, and give
its secret in a Secret (none for a public client):

```sh
kubectl -n paindash create secret generic paindash-oidc \
  --from-literal=client-secret="$CLIENT_SECRET"
```

```yaml
auth:
  mode: oidc
  publicUrl: https://paindash.example.com
  oidc:
    issuer: https://keycloak.example.com/realms/main
    clientId: paindash
    existingSecret: paindash-oidc
    scopes: [openid, email, profile]   # add groups where the provider needs it (Dex)
    groupsClaim: groups                # a dotted path reaches into objects: realm_access.roles
  allowedGroups: [paindash]
  editorGroups: [paindash-admin]
```

A user is named by the `email` claim (unless `email_verified` is false), else `preferred_username`,
else `sub`; groups are read at sign-in. The provider is discovered at the first sign-in, so
paindash starts while it is unreachable. Signing out of paindash does not sign out of the provider:
signing in again can be immediate.

**Local accounts (`local`).** For a few users without an identity provider: a Secret holding one
account per line, `name:bcrypt-hash[:group,...]` (the format of `htpasswd -nB`). Hash each password
(12 characters at least) with the image:

```sh
docker run --rm -it ghcr.io/n0cl0ud/paindash:<version> hash-password
cat > users <<'EOF'
alice@example.com:$2a$12$...:sec
bob@example.com:$2a$12$...
EOF
kubectl -n paindash create secret generic paindash-users --from-file=users
```

```yaml
auth:
  mode: local
  publicUrl: https://paindash.example.com
  local:
    existingSecret: paindash-users
  editorGroups: [sec]                # Alice records exceptions, Bob reads
```

paindash reads the file again when the Secret changes: an account added, removed or given a new
password applies within a couple of minutes, without a restart, and the last two sign that account
out. To lock an account and keep its line, put `*` in front of its hash, or in place of it: it is
signed out, and its sign-ins fail as with a wrong password until the `*` is removed. Putting a
line back as it was revives its sessions that have not expired; a new password ends them for good.
Sign-in is rate-limited: after 5 wrong passwords in 15 minutes an account is refused until the
first one is 15 minutes old, and 30 failures within a minute, across accounts, refuse every
sign-in for that minute.

**Sessions** of `oidc` and `local` are an encrypted cookie, HttpOnly and SameSite=Lax (Secure, with
the `__Host-` prefix, over HTTPS), valid `auth.sessionTtl` (12 h by default). paindash creates its
key in its database (table `secrets`; deleting the row signs everyone out at the next restart).
Nothing is stored server-side: signing out deletes the cookie, a copy of it stays valid until it
expires. `auth.publicUrl` must be the URL browsers use: the sign-in form only accepts posts from
that origin. Use https: over plain http, passwords and cookies travel unencrypted, and paindash
warns at startup unless the host is `localhost` (a local test).

**Other authenticating proxies.** Set `auth.mode=disabled` and put paindash behind the proxy
(oauth2-proxy, an Ingress with external authentication...). Then **anyone who reaches port 8080
can read everything and record exceptions, attributed to "anonymous"**: only the proxy may reach
it. Restrict it with a NetworkPolicy, and never expose the Service directly.

Port 9090 (`/metrics`, `/healthz`, `/readyz`) is never authenticated: keep it off every route.

## Exposure classification

Each workload is marked internet-facing, internal or not exposed, from the Services that route to
its pods; the widest exposure wins.

- **Traefik IngressRoutes:** routes on an entrypoint of `exposure.publicEntrypoints` (default `web`,
  `websecure`) are internet-facing; entrypoints ending in `-internal` or `-int` are internal. Any
  other entrypoint counts as internet-facing and is logged once (`unclassified Traefik
  entrypoint`): list your public ones.
- **Ingresses:** by class, from `exposure.ingressClasses` (`class: internet|internal`). Unlisted
  classes are internal when their name contains `internal` or `private`, internet-facing
  otherwise; so are Ingresses without a class.
- **LoadBalancer Services:** internal when the load balancer has a private IP (RFC 1918, or
  `fc00::/7`) or a hostname containing `internal` (AWS internal Classic Load Balancers),
  internet-facing otherwise.

EndpointSlices name the pods behind a Service, host network ones included. Endpoints only give
IPs, which host network pods share with their node: with Endpoints alone, those pods are not
attributed. When none of the routing series exist, or a cluster has routes but neither EndpointSlice
nor Endpoints series (the log names it), paindash reports exposure as unavailable rather than
marking workloads unexposed.

Known limits:

- **Overstated:** an internal AWS Network Load Balancer (the AWS Load Balancer Controller's
  default) has no `internal` marker in its hostname and counts as internet-facing.
- **Understated:** a load balancer with a private IP that a NAT or a port forwarding exposes to the
  internet (MetalLB on premises, for one) counts as internal; an Ingress with only a
  `defaultBackend` (no rules) has no `kube_ingress_path` series and exposes nothing; Gateway API
  routes, OpenShift Routes, Istio gateways and NodePorts are not read.

## Upgrades

```sh
helm upgrade paindash deploy/helm/paindash -n paindash -f values.yaml
```

- The schema is migrated at startup, each migration in a transaction. There are no down
  migrations: back up the database before upgrading, and restore it to roll back across a
  schema change.
- One replica, `Recreate` strategy: the old pod stops before the new one starts, so the UI is
  unavailable for a few seconds. The grype DB on the PersistentVolumeClaim is kept.
