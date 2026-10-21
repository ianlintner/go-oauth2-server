-- RFC 8628 device authorizations. Only SHA-256 hashes of the device_code and
-- of the normalized user_code are stored. status is the single decision latch
-- (pending -> approved | denied); consumed_at latches the one token issuance.
-- Times are INTEGER Unix nanoseconds, UTC.
CREATE TABLE device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code_hash   TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    scope            TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied')),
    user_id          TEXT NOT NULL,
    expires_at       INTEGER NOT NULL,
    poll_interval    INTEGER NOT NULL,
    last_poll_at     INTEGER,
    consumed_at      INTEGER
) STRICT;
