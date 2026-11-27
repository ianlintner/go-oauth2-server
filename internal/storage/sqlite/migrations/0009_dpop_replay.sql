-- DPoP (RFC 9449 §11.1) proof replay store. jti_key is the base64url SHA-256 of
-- the proof key thumbprint and jti, so no proof material is stored. A row is
-- live until expires_at (Unix nanoseconds, UTC); expired rows are purged lazily.
CREATE TABLE dpop_replay (
    jti_key    TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX dpop_replay_expires_at ON dpop_replay (expires_at);
