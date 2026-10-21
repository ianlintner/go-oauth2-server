-- RFC 9126 pushed authorization requests. Only the SHA-256 hash of the
-- request_uri is stored; consumed_at is the single-use latch.
CREATE TABLE pushed_requests (
    uri_hash       TEXT PRIMARY KEY,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    scope          TEXT NOT NULL,
    state          TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    nonce          TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    consumed_at    INTEGER
) STRICT;
