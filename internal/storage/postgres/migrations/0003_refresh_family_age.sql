-- A rotation family's start time, carried on every member so a rotation cannot
-- extend the family's lifetime. 0 means unknown (rows written before this
-- migration); the service then derives the start from the token's own expiry.
ALTER TABLE refresh_tokens ADD COLUMN family_created_at bigint NOT NULL DEFAULT 0;
