-- RFC 9449 §5: a public client's refresh token is bound to the DPoP proof key.
-- dpop_jkt is the RFC 7638 thumbprint of that key; '' means unbound (every row
-- written before this migration, and every confidential client's token).
ALTER TABLE refresh_tokens ADD COLUMN dpop_jkt TEXT NOT NULL DEFAULT '';
