# go-oauth2-server

Go port of [`rust-oauth2-server`](https://github.com/ianlintner/rust-oauth2-server), developed against the shared cross-language conformance fixtures used by [`typescript-oauth2-server`](https://github.com/ianlintner/typescript-oauth2-server).

**Status:** CI bootstrap plus a health-only server skeleton. The only route is `GET /healthz`; no OAuth2 endpoints exist yet and nothing here is spec-compliant or production-ready. See [`docs/architecture-proposal.md`](docs/architecture-proposal.md) for the planned stack, stages and conformance approach.

## Conformance contract

The shared contract repo `ianlintner/oauth2-conformance` is pinned by commit in [`conformance-contract.yaml`](conformance-contract.yaml) (deliberately not `conformance.yaml`, which is reserved for the implementation manifest once a profile can be claimed). It is not vendored: CI checks the pinned commit out and runs its published runner via an SUT-free self-test ([`scripts/contract-selftest.sh`](scripts/contract-selftest.sh)) that asserts a known match exits 0 and known mismatches (wrong status, wrong body) exit 1.

## Building and testing

```
go build ./...
go test -race ./...
go vet ./...
```

CI additionally runs staticcheck and govulncheck (both version-pinned) inside the single `verify` check, which also runs the contract self-test.
