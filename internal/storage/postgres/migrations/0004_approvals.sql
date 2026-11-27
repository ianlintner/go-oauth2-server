-- Resource-owner approvals of clients: one row per (user, client) holding the
-- approved scope set (JSON array text). A request is auto-approved only by an
-- explicit row here.
CREATE TABLE approvals (user_id text NOT NULL, client_id text NOT NULL,
 scopes text NOT NULL, granted_at bigint NOT NULL, PRIMARY KEY (user_id, client_id));
