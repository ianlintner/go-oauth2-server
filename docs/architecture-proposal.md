# Go OAuth2 server — architecture proposal

Status: proposed, not implemented. Reference: `ianlintner/rust-oauth2-server` on `main` (inventoried at `f6206d8`). Sibling port: `ianlintner/typescript-oauth2-server` (fixtures and route-method inventory at `d1999bf`). The Rust server is the behavioral reference, not proof that every advertised extension is conformant. Verify each item against current Rust tests, route behavior and RFC text before marking it supported.

## Goal and boundaries

Build a Go authorization server that implements the same protocol behavior and security invariants as the Rust server in staged, testable slices. Keep endpoint names and wire behavior compatible where intentional; record explicit deviations and deferred features in a conformance matrix. Do not copy Rust's actor/concurrency machinery literally. No release or claim of spec compliance until a published fixture/test matrix passes for the implemented slice.

Out of initial scope: UI parity, Kubernetes, Kafka/RabbitMQ, MongoDB, a distributed tracing backend, social-login providers, the Rust agent/A2A extensions, dynamic registration, PAR, device grant, DPoP and mTLS. These are later parity waves, not permanent exclusions; the architecture leaves explicit extension points without implementing them prematurely.

## Proposed stack

- Go (current stable, `go.mod` toolchain pinned), single module, `cmd/oauth2-server` plus `internal/` packages. Standard library `net/http` with the Go 1.22+ method/path `ServeMux`; no web framework and no OAuth middleware that hides protocol behavior.
- `github.com/go-jose/go-jose/v4` for JWS/JWK/JWT; `crypto/*` and `golang.org/x/crypto` (argon2id) for primitives. Never implement signature or KDF algorithms ourselves. Parse forms explicitly and reject duplicated OAuth parameters *before* reading values (`r.PostForm` multi-value check), since `FormValue` silently takes the first.
- Domain/application layer (`internal/oauth`) independent of HTTP and SQL: typed commands for authorization, token issuance, introspection, revocation, clients, users, sessions and key sets. Inject `Clock`, `Random`, `Signer`/`Verifier` and storage interfaces for deterministic tests. A single typed OAuth error maps once to RFC status, `WWW-Authenticate`/`Cache-Control` headers and JSON body.
- Storage: SQLite first via `modernc.org/sqlite` (pure Go, no cgo) for tests and local operation; PostgreSQL via `pgx/v5` after the storage contract is executable. One shared storage contract test suite runs against every adapter. Explicit transactions and unique constraints for one-time authorization-code consumption and refresh-token rotation/family revocation; no process-local state for security decisions in production mode. Plain SQL migrations embedded with `embed`.
- Config validated at startup; fail closed for missing signing/session secrets, invalid issuer, or insecure production redirect/cookie settings. Signing keys are persisted and rotated deliberately, never regenerated per restart. Secrets stay out of logs, responses and the repository. `log/slog` structured logging with secret redaction.

## Conformance fixtures

Consume the cross-language fixtures already defined in `typescript-oauth2-server` (`fixtures/rfc6749`, `rfc7636`, `rfc9700`, same JSON shape: `id`, `rfc`, `status`, `request`, `expect`, `note`). Vendor a pinned copy under `conformance/fixtures/` with a `SOURCE` file recording the upstream repo and commit; CI fails if the vendored copy drifts from its recorded pin without an explicit update. A later milestone extracts a shared fixtures repository both ports consume. The Go runner (`cmd/conformance`) executes fixtures black-box against any base URL (Rust, TS or Go), normalizes only nondeterministic token/key fields, and exits nonzero naming the method, path, status, header or claim mismatch. CI runs the runner against a known-match and a known-mismatch local responder so a green build cannot hide a false PASS.

## Port map and stages

1. **Architecture and contracts:** this document; owner review before implementation.
2. **CI bootstrap:** `go vet`, `staticcheck`, `govulncheck`, `go test -race`, vendored-fixture schema validation and the conformance-runner self-test, under one named required check.
3. **Skeleton and storage ports:** health endpoint, typed config/errors, clock/random injection, SQLite adapter, storage contract suite, HTTP integration harness.
4. **Authorization code + PKCE:** client fixture, exact redirect URI match, S256 PKCE only, state and `iss` response (RFC 9207), atomic one-time code redemption, confidential/public client authentication, no implicit/ROPC. Maps RFC 6749/7636/9207 and RFC 9700 negative cases (duplicates, wrong redirect, replay, wrong verifier, missing/weak client auth).
5. **Token lifecycle and OIDC baseline:** client credentials, JWT/JWKS with key IDs, refresh rotation and family replay revocation, revocation/introspection, discovery, ID token/nonce, UserInfo. Maps RFC 6750, 7009, 7662, 8414, 9068 and OIDC Core with cross-process persistence checks.
6. **Later waves (separate milestones):** PostgreSQL parity, device grant, PAR, dynamic registration, DPoP, mTLS, observability parity, social login/admin APIs, agent/A2A extensions, then a cross-language parity audit. Each wave is accepted only with negative security cases and protocol fixtures, not endpoint stubs.

## Compatibility target

Match Rust's wire routes and response shapes by default. Where Rust diverges from an RFC, implement the RFC behavior and record the deviation in the matrix; never silently copy an unsafe deviation.

## Exit criteria for the first implementation wave

`go build ./...`, `go vet`, `staticcheck`, `govulncheck` and `go test -race ./...` pass; a local process boots with validated config; the conformance runner executes a representative positive and negative authorization-code/PKCE set against both the Rust and Go servers; code-replay and redirect/PKCE failure paths use atomic persistence; no secrets in fixtures or logs. The README states what is *not* implemented, without claiming full server parity.
