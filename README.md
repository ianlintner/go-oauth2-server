# go-oauth2-server

Go port of [`rust-oauth2-server`](https://github.com/ianlintner/rust-oauth2-server), developed against the shared cross-language conformance fixtures used by [`typescript-oauth2-server`](https://github.com/ianlintner/typescript-oauth2-server).

**Status:** staged OAuth implementation with PostgreSQL storage and opt-in HTTP telemetry; see [`docs/operations-postgres-observability.md`](docs/operations-postgres-observability.md) for limits. Not production-ready and not a claim of full server parity.

## What is implemented

- `internal/config` — validated configuration, fail-closed on missing/insecure values; secrets (`OAUTH2_SESSION_SECRET` and the signing key) stay out of logs, JSON and `%v`.
- `internal/oauth` — typed OAuth error (one mapping point to status/headers/body), the injected `Clock`/`Random`/`Signer` ports, the `Store`/repository ports (clients, users, one-time authorization codes, refresh-token rotation families), plus PKCE (S256), exact redirect-URI matching (including the RFC 8252 loopback any-port rule) and parameter parsing that rejects duplicates before any value is read (RFC 6749 §3.1).
- `internal/authcode` — the authorization-code engine: authorization request validation, one-time code issuance, confidential (`client_secret_basic`/`client_secret_post`) and public client authentication, atomic single-use code redemption, PKCE verification, and a `client_credentials` grant only where a fixture needs a successful token response.
- `internal/session` — stateless HMAC-signed resource-owner session cookie keyed by `OAUTH2_SESSION_SECRET`.
- `internal/server` — `net/http` handlers for `/oauth/authorize`, `/oauth/token` and `/.well-known/oauth-authorization-server`, plus the test-mode `/auth/login` form (conformance only).
- `internal/storage/sqlite` — `modernc.org/sqlite` adapter with embedded plain-SQL migrations. Stores only hashes of codes, tokens and passwords; single-use consumption and family revocation are atomic `UPDATE ... RETURNING` latches.
- `internal/storage/postgres` — pgx/v5 PostgreSQL adapter, verified against the same storage contract suite with disposable schemas in CI.
- `internal/storage/storagetest` — one reusable storage contract suite run against SQLite and PostgreSQL: single-use codes under concurrency, refresh replay, family revocation, transaction atomicity and cross-handle persistence.
- `internal/secret` — argon2id (PHC) hashing for client secrets and user passwords.
- `internal/conformance` — the shared contract's test-mode SUT seed: strict validation + transactional application, reachable only under `OAUTH2_CONFORMANCE_MODE=1`.

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
OAUTH2_ISSUER=https://auth.example.com \
OAUTH2_SIGNING_KEY_FILE=/path/to/signing.key \
OAUTH2_SESSION_SECRET="$(openssl rand -base64 32)" \
  go run ./cmd/oauth2-server
```

Configuration is read from the environment; see `internal/config` for every variable and its validation. `OAUTH2_STORAGE_DSN` defaults to `:memory:` outside production and is refused in production; a `postgres://` URL selects the pgx adapter. `OAUTH2_METRICS_ENABLED=true` enables `/metrics` on the same listener; restrict scraper access at the network edge. The resource-owner login form is present only under `OAUTH2_CONFORMANCE_MODE=1`.

## Building and testing

```sh
go build ./...
go test -race ./...
go vet ./...
scripts/sut-smoke.sh             # black-box: startup, readiness, fail-closed config
scripts/conformance-run.sh .contract  # core profile + supplementary scenarios (SUT=go|rust)
```

CI additionally runs staticcheck and govulncheck (both version-pinned) inside the single `verify` check, which also runs the contract self-test and the SUT smoke test.
