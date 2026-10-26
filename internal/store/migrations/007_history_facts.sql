-- What the history numbers are made of, as validity intervals: one row per
-- (vulnerability, package, workload) of an env while its attributes hold
-- (until is NULL while they do). Any change closes the row and opens a new
-- one, so the numbers of any scope can be recounted at any past time.
CREATE TABLE history_facts (
    id        bigserial   PRIMARY KEY,
    env       text        NOT NULL,
    cluster   text        NOT NULL,
    namespace text        NOT NULL,
    kind      text        NOT NULL,
    name      text        NOT NULL,
    vuln_id   text        NOT NULL,
    pkg_name  text        NOT NULL,
    pkg_type  text        NOT NULL,
    severity  text        NOT NULL,
    kev       boolean     NOT NULL,
    has_fix   boolean     NOT NULL,
    suspect   boolean     NOT NULL,
    covered   boolean     NOT NULL,
    exposure  text        NOT NULL,
    since     timestamptz NOT NULL,
    until     timestamptz
);
CREATE INDEX history_facts_open ON history_facts (env) WHERE until IS NULL;
CREATE INDEX history_facts_env_since ON history_facts (env, since);
