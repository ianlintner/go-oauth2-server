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

1. **Public clients' refresh tokens are bound to the DPoP key (§5).** When a
   public client redeems a code (or device code) with a DPoP proof, the proof
   key's RFC 7638 thumbprint is stored on the refresh token
   (`refresh_tokens.dpop_jkt`). A refresh must carry a proof from the same
   key, else `invalid_grant`; the check runs before rotation so a thief who
   holds the token but not the key cannot burn it. Rotation carries the
   binding forward along the family, and replay/family revocation behave as
   before. A public client's token with no recorded key (issued without DPoP)
   accepts only a refresh *without* a proof, so a stolen unbound token cannot
   be captured onto an attacker's key. Confidential clients' refresh tokens
   stay unbound (permitted by §5, they authenticate) and a refresh yields an
   access token bound to the proof presented with the refresh request.
   Migration `dpop_jkt` defaults to `''` (unbound) and there is no backfill:
   a public client's refresh token cannot predate DPoP support, so no
   existing row needed binding.
2. **Replay store is in-memory, bounded (100 000 entries) and per process.**
   A restart or a second instance forgets seen proofs, so a proof captured
   within its ~90 s window can be replayed across a restart/instance. This is
   the single-process floor of RFC 9449 §11.1; the contract's restart and
   cross-instance scenarios are draft and are **not** satisfied. When the
   store is full the verifier fails closed (`503 temporarily_unavailable` at
   the token endpoint, `invalid_dpop_proof` at a resource) rather than evicting
   live entries, which would let an attacker flush it and replay a proof.
3. **Proofs are checked before client authentication but recorded after it**
   at the token endpoint. The stateless checks (signature, claims, `htm`,
   `htu`, `iat`) run first, so a bad proof is still answered
   `invalid_dpop_proof`; the `jti` is added to the replay store only once the
   client has authenticated and may use the grant, so a caller that fails
   client authentication does not consume replay-store capacity. An
   authenticated client can still use capacity; per-client throttling
   (RFC 9700 §2.5, below) is not yet present.
4. **`htu` is built from the configured issuer, not the `Host` header**, so
   proofs bind to the public origin even behind a proxy. A deployment whose
   public URL differs from `OAUTH2_ISSUER` will reject all proofs.
5. **No server nonce.** `use_dpop_nonce` / `DPoP-Nonce` (RFC 9449 §8–9) are not
   implemented. Without a nonce a client can pre-generate proofs with a chosen
   future `iat` within the 30 s skew; the exposure is bounded by that window.

## Upgrade and rollback (refresh-token binding)

The binding is enforced by the token endpoint code, not by the database. A
token endpoint built before `refresh_tokens.dpop_jkt` existed ignores the
column: sharing the migrated database, it accepts a bound public-client
refresh token **without a proof** and writes an unbound replacement, which
silently removes the binding for that family. So:

- **Rolling upgrades are not supported for this change.** Drain every old
  token endpoint (no instance running the previous build may share the
  database) before any DPoP-bound public-client token is issued. The
  migration alone is safe to apply early; enabling DPoP for public clients is
  what must wait. There is no issuance gate in the server: if instances cannot
  be drained first, do not let public clients present DPoP proofs (for example
  by routing the `DPoP` header away from the token endpoint) until every
  instance runs this build.
- **Rollback requires revoking bound families first.** Before reverting to a
  build that predates this change, revoke every outstanding refresh token with
  a non-empty `dpop_jkt` (for example
  `DELETE FROM refresh_tokens WHERE dpop_jkt <> ''` — rows in
  `refresh_families` for those families may stay) so the old build cannot
  rotate them into unbound tokens. Affected public clients must re-authorize.
  Leave the `dpop_jkt` column in place; the old build ignores it.
- A mixed-version window that has already happened cannot be detected from the
  data: an unbound replacement looks like a token legitimately issued without
  DPoP. If one occurred, revoke the public clients' refresh tokens issued
  during it.

## Not implemented (separate cards)

- RFC 8705 mTLS: certificate-bound tokens, `tls_client_auth`, metadata. The
  contract's `mtls-request` helper does not exist in the runner yet either.
- DPoP server nonces, persistent/shared replay store, `dpop_jkt` at the
  authorization endpoint / PAR.
- RFC 9700 controls beyond those already present: in-process per-client-id
  failure budgets and a concurrent-hash bound now exist (README, "Request
  throttling"), but the contract does not express throttling, so the runner has
  no scenario that exercises them (scenarios `sender-constrained.abuse.*`: the three
  `PASS` lines in the runner are placeholder scenarios that assert only HTTP 200,
  not evidence of rate limiting).

## Conformance status

Pinned contract: `b968cb1`. Of the 35 `sender-constrained` scenarios, 7
are `stable` and exercised against this server in `scripts/conformance-run.sh`:
`dpop.token-type-dpop`, `jti-required`, `jti-replay`, `htm-binding`,
`htu-binding`, `typ-header`, `iat-stale` — all pass. The rest are `draft`
(runner helpers, nonce mode, clock control, mTLS transport missing) and are
reported as DEFER, not as passes. Nothing here asserts RFC 9449 compliance
beyond those fixtures and the unit/handler tests in `internal/dpop` and
`internal/server`.
