-- Headline numbers of each env, counted like the summary tiles: one row when
-- they change (coalesced) and at least one a day. changes lists the events in
-- between that explain the move.
CREATE TABLE history (
    env                   text        NOT NULL,
    taken_at              timestamptz NOT NULL,
    kev                   integer     NOT NULL,
    critical_fixable      integer     NOT NULL,
    high_fixable_internet integer     NOT NULL,
    excepted              integer     NOT NULL,
    changes               jsonb       NOT NULL DEFAULT '[]',
    PRIMARY KEY (env, taken_at)
);
