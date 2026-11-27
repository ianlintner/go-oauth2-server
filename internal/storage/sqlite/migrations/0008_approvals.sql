-- Resource-owner approvals of clients: one row per (user, client) holding the
-- approved scope set (JSON array). A request is auto-approved only by an
-- explicit row here.
CREATE TABLE approvals (
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id)
) STRICT;
