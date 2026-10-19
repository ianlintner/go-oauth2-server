-- OIDC Core 3.1.2.1: the nonce is bound to the code and echoed in the id_token.
ALTER TABLE auth_codes ADD COLUMN nonce TEXT NOT NULL DEFAULT '';
