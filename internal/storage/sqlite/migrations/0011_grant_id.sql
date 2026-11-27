-- Grant linkage: every authorization code, refresh token and access token
-- records the grant it belongs to, so ending a grant can revoke what was
-- issued under it. '' marks rows written before this migration; it is never
-- matched by a grant revocation.
ALTER TABLE auth_codes ADD COLUMN grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN grant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE access_tokens ADD COLUMN grant_id TEXT NOT NULL DEFAULT '';
CREATE INDEX access_tokens_grant_idx ON access_tokens(grant_id);

-- Grants that have been revoked. An access token created under a revoked grant
-- is dead on arrival, so a revocation cannot be outrun by a concurrent issuance.
CREATE TABLE revoked_grants (
    grant_id   TEXT PRIMARY KEY,
    revoked_at BIGINT NOT NULL
);
