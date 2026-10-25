-- Secrets paindash generates itself, created on first use: the key that seals
-- session cookies ("session"). Kept out of state, which the read model loads.
CREATE TABLE secrets (
    name       text PRIMARY KEY,
    value      bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
