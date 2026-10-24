-- How each vulnerable package was identified, and where in the image.
ALTER TABLE findings ADD COLUMN source text NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN location text NOT NULL DEFAULT '';

-- OpenVEX "not_affected" statements. Never deleted: revoked or expired ones
-- stay for the audit trail.
CREATE TABLE exceptions (
    id              bigserial PRIMARY KEY,
    vuln_id         text NOT NULL,
    pkg_name        text NOT NULL,
    namespace       text NOT NULL DEFAULT '', -- '' = any namespace
    workload        text NOT NULL DEFAULT '', -- '' = any workload
    justification   text NOT NULL,
    statement       text NOT NULL,
    author          text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    revoked_by      text,
    expiry_notified boolean NOT NULL DEFAULT false
);
CREATE INDEX exceptions_vuln ON exceptions (vuln_id);
