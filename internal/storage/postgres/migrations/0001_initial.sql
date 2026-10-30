-- PostgreSQL schema for the shared storage contract. Times are UTC Unix nanoseconds.
-- List columns contain JSON arrays encoded as text, matching the SQLite adapter.
CREATE TABLE clients (id text PRIMARY KEY, name text NOT NULL, secret_hash text NOT NULL,
 auth_method text NOT NULL, public integer NOT NULL CHECK (public IN (0,1)),
 redirect_uris text NOT NULL, scopes text NOT NULL, grant_types text NOT NULL);
CREATE TABLE users (id text PRIMARY KEY, username text NOT NULL UNIQUE,
 password_hash text NOT NULL, email text NOT NULL, scopes text NOT NULL);
CREATE TABLE auth_codes (code_hash text PRIMARY KEY, client_id text NOT NULL,
 user_id text NOT NULL, redirect_uri text NOT NULL, scope text NOT NULL,
 code_challenge text NOT NULL, code_challenge_method text NOT NULL, nonce text NOT NULL DEFAULT '',
 expires_at bigint NOT NULL, consumed_at bigint);
CREATE TABLE refresh_tokens (token_hash text PRIMARY KEY, family_id text NOT NULL,
 client_id text NOT NULL, user_id text NOT NULL, scope text NOT NULL,
 expires_at bigint NOT NULL, rotated_at bigint);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
CREATE TABLE refresh_families (family_id text PRIMARY KEY, revoked_at bigint NOT NULL);
CREATE TABLE access_tokens (jti text PRIMARY KEY, client_id text NOT NULL, user_id text NOT NULL,
 scope text NOT NULL, issued_at bigint NOT NULL, expires_at bigint NOT NULL, revoked_at bigint);
CREATE INDEX access_tokens_client_idx ON access_tokens(client_id);
CREATE TABLE device_codes (device_code_hash text PRIMARY KEY, user_code_hash text NOT NULL UNIQUE,
 client_id text NOT NULL, scope text NOT NULL, status text NOT NULL CHECK(status IN ('pending','approved','denied')),
 user_id text NOT NULL, expires_at bigint NOT NULL, poll_interval integer NOT NULL,
 last_poll_at bigint, consumed_at bigint);
CREATE TABLE pushed_requests (uri_hash text PRIMARY KEY, client_id text NOT NULL,
 redirect_uri text NOT NULL, scope text NOT NULL, state text NOT NULL,
 code_challenge text NOT NULL, nonce text NOT NULL, expires_at bigint NOT NULL, consumed_at bigint);
