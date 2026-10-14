-- Initial schema. Hashes (never raw secrets, codes or tokens) are stored.
-- Times are INTEGER Unix nanoseconds, UTC. List columns are JSON arrays.

CREATE TABLE clients (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    secret_hash   TEXT NOT NULL,
    auth_method   TEXT NOT NULL,
    public        INTEGER NOT NULL CHECK (public IN (0, 1)),
    redirect_uris TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    grant_types   TEXT NOT NULL
) STRICT;

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email         TEXT NOT NULL,
    scopes        TEXT NOT NULL
) STRICT;

-- consumed_at is the single-use latch: NULL until the one successful Consume.
CREATE TABLE auth_codes (
    code_hash             TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    expires_at            INTEGER NOT NULL,
    consumed_at           INTEGER
) STRICT;

-- rotated_at is the rotation latch; a family listed in refresh_families is
-- revoked, which blocks every member, including tokens inserted afterwards.
CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id  TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    scope      TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    rotated_at INTEGER
) STRICT;

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

CREATE TABLE refresh_families (
    family_id  TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
) STRICT;
