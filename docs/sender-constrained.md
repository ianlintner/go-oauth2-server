# Sender-constrained tokens — DPoP slice (v0.5)

Owner security review is required before this becomes production behavior. It
introduces new trust-boundary code (proof verification, key binding, replay
state); nothing here is a release or deployment.

This PR implements the **RFC 9449 DPoP** portion of the v0.5 milestone. mTLS
(RFC 8705) and the remaining RFC 9700 controls are **not** in this change and
are not claimed (see "Not implemented").

## What is implemented

- `internal/dpop`: proof verifier. Accepts exactly one `DPoP` header whose JWS
  is `typ=dpop+jwt`, signed with ES256/ES384/EdDSA (never `none` or MAC) by
  the public key in its `jwk` header (a `jwk` carrying a private key is
  rejected). Required claims: `jti`, `htm` (== request method), `htu` (== the
  configured public issuer origin + request path; the request's query and
  fragment are ignored, a proof `htu` carrying them is rejected), `iat`
  (60 s old / 30 s ahead window). At a resource `ath` must equal
  `base64url(SHA-256(access token))`; at the token endpoint `ath` is refused.
- `jti` replay detection, scoped per proof key (`SHA-256(jkt || 0x00 || jti)`),
  evaluated **after** every other check so a rejected proof never burns its jti.
- Token endpoint: a valid proof binds the issued JWT access token with
  `cnf.jkt` and answers `token_type: DPoP`. No proof → ordinary Bearer token.
  Bad proof → `400 invalid_dpop_proof` (generic description; which check
  failed is not disclosed).
- `/oauth/userinfo`: a bound token must be presented with `Authorization: DPoP`
  and a matching proof (`ath`, key == `cnf.jkt`); presented as Bearer it is
  `401 invalid_token`. An unbound token under the `DPoP` scheme is also
  `invalid_token` (no upgrade by attaching an attacker key).
- Introspection reports `token_type: DPoP` and `cnf.jkt` for bound tokens.
- Discovery advertises `dpop_signing_alg_values_supported`.
- A token carrying a `cnf` this server did not mint (anything without a
  non-empty `jkt`) is treated as invalid, never as unbound.

## Decisions that need the owner's review

1. **Public clients cannot use DPoP.** RFC 9449 §5 requires a public client's
   refresh token to be bound to the proof key. That binding needs a schema
   change and is deferred, so a DPoP request from a public client is refused
   (`invalid_request`) instead of issuing a bound access token beside an
   unbound refresh token. Confidential clients' refresh tokens stay unbound
   (permitted by §5) and a refresh yields an access token bound to the proof
   presented with the refresh request.
2. **Replay store is in-memory, bounded (100 000 entries) and per process.**
   A restart or a second instance forgets seen proofs, so a proof captured
   within its ~90 s window can be replayed across a restart/instance. This is
   the single-process floor of RFC 9449 §11.1; the contract's restart and
   cross-instance scenarios are draft and are **not** satisfied. When the
   store is full the verifier fails closed (`503 temporarily_unavailable` at
   the token endpoint, `invalid_dpop_proof` at a resource) rather than evicting
   live entries, which would let an attacker flush it and replay a proof.
3. **Proofs are verified before client authentication** at the token endpoint,
   so an unauthenticated caller can consume replay-store capacity with valid
   self-signed proofs (a fail-closed denial of service of DPoP issuance, bounded
   by the 90 s lifetime). Rate limiting (RFC 9700 §2.5, below) is the intended
   mitigation and is not yet present.
4. **`htu` is built from the configured issuer, not the `Host` header**, so
   proofs bind to the public origin even behind a proxy. A deployment whose
   public URL differs from `OAUTH2_ISSUER` will reject all proofs.
5. **No server nonce.** `use_dpop_nonce` / `DPoP-Nonce` (RFC 9449 §8–9) are not
   implemented. Without a nonce a client can pre-generate proofs with a chosen
   future `iat` within the 30 s skew; the exposure is bounded by that window.

## Not implemented (separate cards)

- RFC 8705 mTLS: certificate-bound tokens, `tls_client_auth`, metadata. The
  contract's `mtls-request` helper does not exist in the runner yet either.
- DPoP server nonces, persistent/shared replay store, refresh-token binding for
  public clients, `dpop_jkt` at the authorization endpoint / PAR.
- RFC 9700 controls beyond those already present: per-client rate limiting and
  invalid-client throttling (scenarios `sender-constrained.abuse.*`: the three
  `PASS` lines in the runner are placeholder scenarios that assert only HTTP 200,
  not evidence of rate limiting).

## Conformance status

Pinned contract: `985fef7` (v0.5). Of the 35 `sender-constrained` scenarios, 7
are `stable` and exercised against this server in `scripts/conformance-run.sh`:
`dpop.token-type-dpop`, `jti-required`, `jti-replay`, `htm-binding`,
`htu-binding`, `typ-header`, `iat-stale` — all pass. The rest are `draft`
(runner helpers, nonce mode, clock control, mTLS transport missing) and are
reported as DEFER, not as passes. Nothing here asserts RFC 9449 compliance
beyond those fixtures and the unit/handler tests in `internal/dpop` and
`internal/server`.
