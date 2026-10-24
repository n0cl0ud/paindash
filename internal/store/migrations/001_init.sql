-- Images are keyed by manifest digest: the same digest promoted from test to
-- prod is scanned once.
CREATE TABLE images (
    digest      text PRIMARY KEY,
    ref         text NOT NULL,                    -- pullable repo@sha256:...
    status      text NOT NULL DEFAULT 'pending',  -- pending|scanning|scanned|failed
    error       text,
    attempts    int NOT NULL DEFAULT 0,
    retry_at    timestamptz,                      -- backoff after a failed attempt
    quiet       boolean NOT NULL DEFAULT false,   -- discovered by the initial sync: no per-image events
    first_seen  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz,                      -- stopped running; pruned after the retention period
    sbom        bytea,                            -- gzipped syft JSON
    sbom_at     timestamptz,
    matched_at  timestamptz,
    db_built_at timestamptz
);

-- Current runtime inventory. Rows are deleted when they stop running.
CREATE TABLE containers (
    env        text NOT NULL,
    cluster    text NOT NULL,
    namespace  text NOT NULL,
    kind       text NOT NULL,
    name       text NOT NULL,
    container  text NOT NULL,
    digest     text NOT NULL REFERENCES images (digest),
    image      text NOT NULL,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster, namespace, kind, name, container, digest)
);
CREATE INDEX containers_digest ON containers (digest);

-- Append-only deployment history, used to compare a new image with the
-- previous one of the same workload container.
CREATE TABLE deployments (
    id          bigserial PRIMARY KEY,
    env         text NOT NULL,
    cluster     text NOT NULL,
    namespace   text NOT NULL,
    kind        text NOT NULL,
    name        text NOT NULL,
    container   text NOT NULL,
    digest      text NOT NULL,
    image       text NOT NULL,
    deployed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX deployments_slot ON deployments (cluster, namespace, kind, name, container, deployed_at DESC);

CREATE TABLE vulns (
    id              text PRIMARY KEY,
    aliases         text[] NOT NULL DEFAULT '{}',
    severity        text NOT NULL,
    cvss            double precision,
    epss            double precision,
    epss_percentile double precision,
    kev             boolean NOT NULL DEFAULT false,
    kev_added       timestamptz,
    description     text NOT NULL DEFAULT '',
    url             text NOT NULL DEFAULT '',
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    digest      text NOT NULL REFERENCES images (digest) ON DELETE CASCADE,
    vuln_id     text NOT NULL REFERENCES vulns (id),
    pkg_name    text NOT NULL,
    pkg_version text NOT NULL,
    pkg_type    text NOT NULL,
    purl        text NOT NULL,
    fixed_in    text[] NOT NULL DEFAULT '{}',
    first_seen  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (digest, vuln_id, purl)
);
CREATE INDEX findings_vuln ON findings (vuln_id);

CREATE TABLE events (
    id       bigserial PRIMARY KEY,
    ts       timestamptz NOT NULL DEFAULT now(),
    env      text NOT NULL,              -- '*' for events concerning every env
    cluster  text NOT NULL DEFAULT '',
    type     text NOT NULL,
    title    text NOT NULL,
    severity text,
    workload jsonb,
    image    text,
    delta    jsonb
);
CREATE INDEX events_env ON events (env, id DESC);

CREATE TABLE state (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
