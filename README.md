# go-oauth2-server

Go port of [`rust-oauth2-server`](https://github.com/ianlintner/rust-oauth2-server), developed against the shared cross-language conformance fixtures used by [`typescript-oauth2-server`](https://github.com/ianlintner/typescript-oauth2-server).

**Status:** staged OAuth implementation with PostgreSQL storage and opt-in HTTP telemetry; see [`docs/operations-postgres-observability.md`](docs/operations-postgres-observability.md) for limits. Not production-ready and not a claim of full server parity.

## What is implemented

- `internal/config` — validated configuration, fail-closed on missing/insecure values; secrets (`OAUTH2_SESSION_SECRET` and the signing key) stay out of logs, JSON and `%v`.
- `internal/oauth` — typed OAuth error (one mapping point to status/headers/body), the injected `Clock`/`Random`/`Signer` ports, the `Store`/repository ports (clients, users, one-time authorization codes, refresh-token rotation families), plus PKCE (S256), exact redirect-URI matching (including the RFC 8252 loopback any-port rule, with one shared scheme allow-list applied at registration, seed load and match time: https, loopback http, or a dotted private-use scheme) and parameter parsing that rejects duplicates before any value is read (RFC 6749 §3.1).
- `internal/authcode` — the authorization-code engine: authorization request validation, one-time code issuance, confidential (`client_secret_basic`/`client_secret_post`) and public client authentication, atomic single-use code redemption, PKCE verification, and a `client_credentials` grant only where a fixture needs a successful token response.
- `internal/session` — stateless HMAC-signed resource-owner session cookie keyed by `OAUTH2_SESSION_SECRET`.
- `internal/server` — `net/http` handlers for `/oauth/authorize`, `/oauth/token` and `/.well-known/oauth-authorization-server`, plus the test-mode `/auth/login` form (conformance only).
- `internal/storage/sqlite` — `modernc.org/sqlite` adapter with embedded plain-SQL migrations. Stores only hashes of codes, tokens and passwords; single-use consumption and family revocation are atomic `UPDATE ... RETURNING` latches.
- `internal/storage/postgres` — pgx/v5 PostgreSQL adapter, verified against the same storage contract suite with disposable schemas in CI.
- `internal/storage/storagetest` — one reusable storage contract suite run against SQLite and PostgreSQL: single-use codes under concurrency, refresh replay, family revocation, transaction atomicity and cross-handle persistence.
- `internal/secret` — argon2id (PHC) hashing for client secrets and user passwords.
- `internal/conformance` — the shared contract's test-mode SUT seed: strict validation + transactional application, reachable only under `OAUTH2_CONFORMANCE_MODE=1`.

## Endpoint access notes

- `/oauth/introspect` requires an authenticated (confidential) client; a public client identified only by `client_id` receives `401 invalid_client`, and discovery no longer lists `none` for introspection. `/oauth/revoke` still accepts public clients (RFC 7009 §2.1).
- `/oauth/userinfo` serves only tokens carrying the `openid` scope; other tokens receive `403 insufficient_scope`. The client credentials grant refuses the `openid` scope, so UserInfo never returns a client identifier as `sub`.

## What is deliberately not implemented

- Implicit and ROPC grants (rejected), social login and administrative APIs; no OpenTelemetry span export or collector. Only the profiles named in `conformance.yaml` are exercised against the pinned contract, not the unfinished `operations` profile.
- No production deployment, release, or claim of spec compliance beyond the fixtures below passing.

## Conformance contract

The shared contract repo `ianlintner/oauth2-conformance` is pinned by commit in [`conformance-contract.yaml`](conformance-contract.yaml); [`conformance.yaml`](conformance.yaml) records the currently claimed profiles. It is not vendored: CI checks the pinned commit out and runs its published runner.

- [`scripts/contract-selftest.sh`](scripts/contract-selftest.sh) is an SUT-free self-test of the runner (known match exits 0, known mismatches exit 1).
- [`scripts/conformance-run.sh`](scripts/conformance-run.sh) starts this server (or the Rust reference) in conformance mode and runs the profiles currently claimed in `conformance.yaml` plus supplementary scenarios in [`conformance/scenarios`](conformance/scenarios).

The runner distinguishes stable passing scenarios from deferred draft scenarios; a passing run is not an `operations` claim or complete standards compliance.

## Running

```sh
OAUTH2_ENVIRONMENT=development \
OAUTH2_ISSUER=https://auth.example.com \
OAUTH2_SIGNING_KEY_FILE=/path/to/signing.key \
OAUTH2_SESSION_SECRET="$(openssl rand -base64 32)" \
  go run ./cmd/oauth2-server
```

Configuration is read from the environment; see `internal/config` for every variable and its validation. `OAUTH2_ENVIRONMENT` selects the validation profile (`development`, `test` or `production`). **When it is unset or empty the server runs as `production`**, so relaxed behavior (http issuer, in-memory storage, insecure redirects, conformance mode) requires an explicit `development` or `test` value; deployments that relied on the former implicit `development` default must now set it. `OAUTH2_STORAGE_DSN` defaults to `:memory:` outside production and is refused in production; a `postgres://` URL selects the pgx adapter, and in production it must carry `sslmode=require`, `verify-ca` or `verify-full`. The signing key must be an RSA key of at least 2048 bits, and its file must not be accessible by group or other (for example mode `0600`; not checked on Windows). HTTP server limits are configurable with `OAUTH2_READ_TIMEOUT` (default `30s`), `OAUTH2_WRITE_TIMEOUT` (`60s`), `OAUTH2_IDLE_TIMEOUT` (`120s`) and `OAUTH2_MAX_HEADER_BYTES` (`32768`); raise them deliberately when running behind a slow proxy. `OAUTH2_METRICS_ENABLED=true` enables `/metrics` on the same listener; restrict scraper access at the network edge. The resource-owner login form is present only under `OAUTH2_CONFORMANCE_MODE=1`.

### Request throttling

Password-hash work is bounded in-process:

- `OAUTH2_MAX_CONCURRENT_HASHES` caps concurrent argon2id computations (default: one per CPU). A request that cannot take a slot immediately is answered `429` with `{"error":"temporarily_unavailable"}`; nothing is queued.
- `OAUTH2_AUTH_FAILURES_PER_MINUTE` (default `10`) caps failed authentications per presented client id (token, introspection, revocation and PAR endpoints) and per presented username at `/auth/login`; login also has a per-source budget (5× the value) keyed on the connection's peer address only, never a forwarded header. Over-budget keys get the same `429` before any hash is computed, whether or not the id exists. Successful authentications do not consume budget.
- A negative value disables the corresponding limit. Conformance mode defaults both to disabled unless set.

The limiters are per process: with several replicas the effective budgets multiply by the replica count. Clients that previously saw `401 invalid_client` for a burst of failures now see `429 temporarily_unavailable` once over budget.

## Building and testing

```sh
go build ./...
go test -race ./...
go vet ./...
scripts/sut-smoke.sh             # black-box: startup, readiness, fail-closed config
scripts/conformance-run.sh .contract  # core profile + supplementary scenarios (SUT=go|rust)
```

CI additionally runs staticcheck and govulncheck (both version-pinned) inside the single `verify` check, which also runs the contract self-test and the SUT smoke test.
