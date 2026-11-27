-- Server-side resource-owner sessions. id is the SHA-256 hash of the session
-- identifier carried in the cookie; revoked_at is set when the session is ended.
CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
) STRICT;
CREATE INDEX sessions_username ON sessions (username);
