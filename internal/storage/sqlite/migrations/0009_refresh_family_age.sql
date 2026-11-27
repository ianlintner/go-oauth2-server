-- A rotation family's start time, carried on every member so a rotation cannot
-- extend the family's lifetime. Existing rows are backfilled from the earliest
-- retained member of their family: its expiry minus the default 30-day token
-- lifetime (nanoseconds). This is a best-effort estimate of the first token's
-- issue time; any row left at 0 is handled by the service.
ALTER TABLE refresh_tokens ADD COLUMN family_created_at INTEGER NOT NULL DEFAULT 0;
UPDATE refresh_tokens SET family_created_at =
  (SELECT MIN(r.expires_at) FROM refresh_tokens r WHERE r.family_id = refresh_tokens.family_id) - 2592000000000000;
