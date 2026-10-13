# go-oauth2-server

Go port of [`rust-oauth2-server`](https://github.com/ianlintner/rust-oauth2-server), developed against the shared cross-language conformance fixtures used by [`typescript-oauth2-server`](https://github.com/ianlintner/typescript-oauth2-server).

**Status:** skeleton and storage ports (stage 3 of [`docs/architecture-proposal.md`](docs/architecture-proposal.md)). The server validates configuration fail-closed, opens storage, and serves only the health probes (`GET /healthz` liveness, `GET /health` readiness). No OAuth grant endpoints exist yet and nothing here is spec-compliant or production-ready.

## What is in this milestone

- `internal/config` — validated configuration, fail-closed on missing/insecure values; secrets (`OAUTH2_SESSION_SECRET` and the signing key) stay out of logs, JSON and `%v`.
- `internal/oauth` — typed OAuth error (one mapping point to status/headers/body), the injected `Clock`/`Random`/`Signer` ports, and the `Store`/repository ports (clients, users, one-time authorization codes, refresh-token rotation families).
- `internal/storage/sqlite` — `modernc.org/sqlite` adapter with embedded plain-SQL migrations. Stores only hashes of codes, tokens and passwords; single-use consumption and family revocation are atomic `UPDATE ... RETURNING` latches.
- `internal/storage/storagetest` — one reusable storage contract suite run against every adapter (SQLite now, PostgreSQL later): single-use codes under concurrency, refresh replay, family revocation, transaction atomicity and cross-handle persistence.
- `internal/secret` — argon2id (PHC) hashing for client secrets and user passwords.
- `internal/conformance` — the shared contract's test-mode SUT seed: strict validation + transactional application, reachable only under `OAUTH2_CONFORMANCE_MODE=1`.

## Conformance contract

The shared contract repo `ianlintner/oauth2-conformance` is pinned by commit in [`conformance-contract.yaml`](conformance-contract.yaml) (deliberately not `conformance.yaml`, which is reserved for the implementation manifest once a profile can be claimed). It is not vendored: CI checks the pinned commit out and runs its published runner via an SUT-free self-test ([`scripts/contract-selftest.sh`](scripts/contract-selftest.sh)) that asserts a known match exits 0 and known mismatches (wrong status, wrong body) exit 1.

The test-mode SUT interface (seed file, non-interactive login, readiness) is part of this milestone, but no grant endpoints are implemented, so **no profile is claimed and no conformance scenarios run against this server yet.**

## Running

```sh
OAUTH2_ISSUER=https://auth.example.com \
OAUTH2_SIGNING_KEY_FILE=/path/to/signing.key \
OAUTH2_SESSION_SECRET="$(openssl rand -base64 32)" \
  go run ./cmd/oauth2-server
```

Configuration is read from the environment; see `internal/config` for every variable and its validation. `OAUTH2_STORAGE_DSN` defaults to `:memory:` outside production and is refused in production.

## Building and testing

```sh
go build ./...
go test -race ./...
go vet ./...
scripts/sut-smoke.sh      # black-box: startup, readiness, fail-closed config
```

CI additionally runs staticcheck and govulncheck (both version-pinned) inside the single `verify` check, which also runs the contract self-test and the SUT smoke test.
