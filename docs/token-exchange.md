# RFC 8693 token exchange

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` at `/oauth/token`.
Advertised in discovery whenever the token service is wired.

## Accepted input
- Client authentication: confidential clients only, registered for the grant.
- `subject_token` + `subject_token_type` (required); `actor_token` +
  `actor_token_type` (optional, both or neither). Types:
  `urn:ietf:params:oauth:token-type:access_token` or `:jwt`.
- Only this server's own live, unrevoked access tokens are accepted. Refresh
  tokens, ID tokens and foreign assertions are refused (`invalid_request` for an
  unsupported type, `invalid_grant` for an invalid/expired/revoked token).
- `requested_token_type` (default access_token; id_token and refresh_token
  are refused with `invalid_request`), `scope`, `resource`, `audience`.
  `authorization_details` is refused.

## Policy
- Scope is only narrowed: a subset of the subject token's scope **and** of the
  calling client's registered scopes (`invalid_scope`).
- Audience is only narrowed: each `resource`/`audience` must be an absolute URI
  the caller may target and must already be in the subject token's `aud`
  (`invalid_target`). Omitted → the subject's audience is kept.
- Cross-client exchange or delegation (an `actor_token`, or a subject token
  issued to another client) requires the **issuing** client to list the caller in
  `Client.AllowedActors` (`allowed_actors` column, seed key `allowed_actors`);
  otherwise `invalid_grant`. The actor token must have been issued to the caller.
- Delegation is recorded in the `act` claim (`{sub, iss, act?}`), surfaced by
  introspection. Chain depth is capped at 4 (`MaxDelegationDepth`).
- A DPoP-bound subject/actor token needs a proof from the same key; the new
  token is bound to the proof presented with the exchange request.
- No refresh token is issued. Response carries `issued_token_type`.

## Not in this slice
RFC 7523 JWT-bearer and `private_key_jwt` (card t_b5035172); foreign-issuer
subject tokens (no trusted-issuer registry yet); `may_act`.
