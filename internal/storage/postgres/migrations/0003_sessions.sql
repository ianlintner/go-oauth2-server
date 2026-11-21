-- Server-side resource-owner sessions. id is the SHA-256 hash of the session
-- identifier carried in the cookie; revoked_at is set when the session is ended.
CREATE TABLE sessions (
    id         text PRIMARY KEY,
    username   text NOT NULL,
    expires_at bigint NOT NULL,
    revoked_at bigint
);
CREATE INDEX sessions_username ON sessions (username);
