# Extended grants — device grant, PAR, dynamic registration (v0.4)

Owner review is required before this becomes production behavior.

**The device grant is conformance-only.** It needs a resource-owner login for
the verification page, and this server has none outside conformance mode. So
`/oauth/device_authorization` and `/oauth/device/verify` are mounted only when
`OAUTH2_CONFORMANCE_MODE=1` (itself refused in production); elsewhere they
return 404, and discovery omits `device_authorization_endpoint` and the device
grant from `grant_types_supported`. Because no device code can be issued
outside conformance mode, a `device_code` token request cannot succeed there
(fail-closed), even though the grant URN is recognized.

This is a
scoped port of the RFC 8628 device grant, RFC 9126 pushed authorization
requests and RFC 7591 dynamic client registration, validated against the
shared `oauth2-conformance` contract's `extended-grants` profile.

## Scope and status

The contract's extended-grants profile contains 51 scenarios. Only the device
grant portion is `stable` today; PAR and registration scenarios are still
`draft` because the contract's runner cannot yet sign client assertions / JWKs
or send duplicate form keys (see the contract's `docs/extended-grants-gaps.md`
"part 3/3" section). This PR therefore:

- claims `extended-grants` (device grant only) via `conformance.yaml`, and
- implements PAR and registration so their draft scenarios pass when the runner
  catches up, **without** claiming conformance for them here.

The card body is explicit: "do not claim spec compliance beyond the fixtures
passing."

## New security design (owner decision required)

These parameters were introduced by this PR and follow the Rust reference where
it is RFC-safe. They are proposed here for owner review, not silently shipped.

1. **Device grant user code.** 8 characters from a 20-symbol alphabet (vowels
   and look-alikes removed), formatted `XXXX-XXXX`, ~34.6 bits. RFC 8628 §6.1
   recommends 20-bit minimum and discourages trivial codes.

2. **Polling interval / slow_down.** Default interval 5s (RFC 8628 §3.2), +5s
   per too-fast poll (RFC 8628 §3.5), capped at 60s. The grown interval
   persists on the record and is never lowered by a racing poller, so a
   misbehaving client cannot ride a lower limit. A spent or denied code never
   answers `slow_down`.

3. **Verification page.** `GET /oauth/device/verify?user_code=…` (signed-in
   users only) shows the requesting client's registered name (or, for a client
   without one, its `client_id` marked as unnamed), the requested scope and the
   code, and offers Approve and Deny. The lookup counts against the same
   per-user failed-entry limit as a decision when the request is marked
   `Sec-Fetch-Site: same-origin` or `none`. A storage error does not count. A
   request marked `cross-site` or `same-site` gets the plain entry form without
   any lookup, and a request without that header is looked up against a
   separate lookup-only window, so lookups the user did not type cannot use up
   the budget that guards decisions. When that window is used up the page
   answers with the entry form instead of an error: the form carries a
   session-bound token and submits the typed code by `POST` with
   `action=lookup`, which needs that token (`403` otherwise) and is charged to
   the decision budget, so a user whose browser omits the header is never
   locked out and nothing off-site can trigger the lookup. The decision `POST` must carry
   the `csrf_token` issued with that page — bound to the session cookie and to
   that user code, valid for 15 minutes — and an `action` of exactly `approve`
   or `deny`; a missing token is `403`, a missing or other `action` is
   `invalid_request`. `Sec-Fetch-Site` is still checked but only as an extra
   layer. The contract runner drives the JSON endpoints and does not render
   this page, so these rules are covered by unit tests only.

4. **User-code entry brute-force limit.** A signed-in user may fail at most
   5 entries per 5 minutes (returning 429), inside `authcode` only. The count
   is a single atomic check-and-record, so concurrent guesses cannot overshoot
   the cap, and a successful entry does not count against it. RFC 8628 §5.2
   requires the endpoint be designed to limit brute-force attempts.

5. **Pushed request lifetime.** `request_uri` is single-use (RFC 9126 §2.2)
   and expires after **60 seconds** — a policy choice; the RFC leaves TTL to
   the AS. `request_uri` is 256-bit random under
   `urn:ietf:params:oauth:request_uri:`; client-bound; resolved only to the
   pushing client.

6. **Dynamic registration policy.** Open registration (no initial access
   token), gated: **refused in production**, implied in conformance mode, and
   opt-in otherwise via `OAUTH2_DYNAMIC_REGISTRATION=1`. A registered client:
   - may hold only `authorization_code`, `refresh_token` and the device grant
     (never `client_credentials` — that would mint machine tokens on demand);
   - may authenticate only by `client_secret_basic`, `client_secret_post` or
     `none`;
   - may register redirect URIs under the authorization endpoint's rules
     (absolute, no fragment/userinfo, https-or-loopback-or-private-scheme);
   - is granted only scopes the operator allows (currently `openid`, `read`),
     and only those it requests.
   - RFC 7591 §2: unrecognized metadata members are **ignored**; understood but
     unsupported ones (`jwks`, `jwks_uri`, `software_statement`) fail with
     `invalid_client_metadata`.
   RFC 7592 client management (read/update/delete) is **out of scope** — its
   scenarios are draft.

## Spec deviations / out of scope

- **TLS.** The conformance SUT runs on a loopback `http` issuer, so the
  RFC-required `https`-scheme requirements (`device-authz-tls`,
  `par-endpoint-https`, `reg-endpoint-tls`) are asserted as metadata shape
  only, exactly as the contract documents.
- `reference-deviation` (`device.access-denied`): RFC 8628 §3.5 says a denied
  device code is a 400 `access_denied`. This server returns 400 (RFC wins over
  the Rust reference, which returns 403).
- JAR, RAR, token exchange, client assertions (RFC 9101/9396/8693/7523) are
  not implemented; their scenarios are draft and remain so.

## Known gaps for a production turn-on (not part of this card)

- **No expiry cleanup** for `device_codes`, `pushed_requests` or dynamically
  registered `clients` rows: a loop of public-client requests fills the store.
- **No per-IP / per-client rate limit** on unauthenticated `/oauth/par` (reachable
  in production) or on `/oauth/device_authorization` and registration (neither is
  reachable in production: the first is conformance-only, the second is refused).
- The user-code failure limiter is **in-process memory**, so it does not span
  replicas; it bounds brute force only per process. The client-authentication
  and login failure budgets and the concurrent-hash bound (README, "Request
  throttling") are per process in the same way. Unauthenticated `/oauth/par`
  and the other endpoints are still not limited per source.
- The user code is stored as an (unsalted) SHA-256 of ~34.6 bits, brute-forceable
  if the database leaks, within its 10-minute TTL.
- A token-assembly failure after `Consume` would burn a device code without
  issuing a token (matching the existing authorization-code path; a `WithTx`
  wrap would make it atomic).

## Verification

- `go build`, `go vet`, `go test -race ./...`, `staticcheck`, `govulncheck`.
- `scripts/conformance-run.sh` runs `core`, `token-lifecycle`, `oidc-basic` and
  `extended-grants` against a locally started server; every `stable` scenario
  must pass and no stable scenario may fail.
