# Supplementary conformance scenarios

Scenarios here extend the shared contract (`ianlintner/oauth2-conformance`,
pinned in `conformance-contract.yaml`) with cases it does not yet express. They
use the contract's own scenario schema, run through the contract's own runner,
and are executed against **both** the Go server and the Rust reference by
`scripts/conformance-run.sh` (`SUT=go` / `SUT=rust`), so one fixture gates both
implementations.

They are not a second harness and not a fork of the contract: they are meant to
be proposed upstream and deleted here once the contract carries them. Their ids
start with `local.` so they can never collide with a contract id.

## Why they exist

`request.query` in the scenario schema is a record, so it cannot send a
parameter twice. The architecture requires duplicated OAuth parameters to be
rejected before any value is read (RFC 6749 section 3.1), and that is only
testable by putting the repeated key in the request path.

| scenario | what a vulnerable server would do |
| --- | --- |
| `duplicate-client-id` | resolve the first or last of two different clients |
| `duplicate-redirect-uri` | validate the registered value, redirect to the other |
| `duplicate-state` | echo an ambiguous value |
| `duplicate-code-challenge-method` | accept `plain` after `S256` (PKCE downgrade) |
| `duplicate-response-type` | accept `token` after `code` (implicit downgrade) |
| `duplicate-identical-value` | treat equal repeats as harmless |

Only the non-redirect `400` is asserted. RFC 6749 does not fix the body format
of an authorization error that cannot be redirected (the Rust reference renders
a text page, this server a JSON object), so asserting it would test rendering,
not security.
