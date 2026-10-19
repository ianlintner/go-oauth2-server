-- Access tokens are persisted so they can be revoked (RFC 7009) and
-- introspected (RFC 7662) across processes. Only the JWT "jti" is stored,
-- not the token value. Times are INTEGER Unix nanoseconds, UTC.
CREATE TABLE access_tokens (
    jti        TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    scope      TEXT NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;

CREATE INDEX access_tokens_client_idx ON access_tokens (client_id);
