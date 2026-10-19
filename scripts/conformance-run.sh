#!/usr/bin/env bash
# Runs the shared contract's core, token-lifecycle and oidc-basic profiles (plus this
# repo's supplementary scenarios) against a locally started system under test.
#
# usage: scripts/conformance-run.sh [CONTRACT_DIR]            (default: .contract)
#
#   SUT=go    (default) build and start this repository's server
#   SUT=rust  start the Rust reference; RUST_SUT_BIN must name a prebuilt
#             rust_oauth2_server binary (the Rust repo is never modified)
#
# The SUT is started in conformance mode (seed + test login) on a
# kernel-assigned port with in-memory storage. The runner is the contract's
# published one. Scenarios are the contract's own plus conformance/scenarios/
# (supplementary, see its README); both sets run against whichever SUT is
# selected, so the same fixtures gate Go and Rust. Exit status is the runner's:
# nonzero when any stable scenario fails.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root="$(pwd)"
contract_dir="$(cd "${1:-.contract}" && pwd)"
sut="${SUT:-go}"
pin="$(sed -n 's/^commit:[[:space:]]*//p' conformance-contract.yaml)"
printf '%s' "$pin" | grep -Eq '^[0-9a-f]{40}$' || { echo "conformance-contract.yaml needs a full 40-hex commit pin" >&2; exit 1; }
actual="$(git -C "$contract_dir" rev-parse HEAD)"
[ "$actual" = "$pin" ] || { echo "contract at $actual, pinned $pin" >&2; exit 1; }

work="$(mktemp -d)"
pid=""
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  find "$work" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

# Ask the kernel for a free port so a stray listener can never answer for us.
port="${CONFORMANCE_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}"

# The contract's reference seed is used unmodified: its issuer
# (http://localhost:8080) is asserted literally by the iss and metadata
# scenarios, so the SUT advertises exactly that issuer while listening on a
# free port. The runner only reaches the SUT through --base-url and never
# follows a redirect, so the listen address and the issuer string are
# independent here.
cp "$contract_dir/examples/seed.yaml" "$work/seed.yaml"
issuer="$(sed -n 's/^issuer:[[:space:]]*//p' "$work/seed.yaml")"
[ -n "$issuer" ] || { echo "seed.yaml has no issuer" >&2; exit 1; }

case "$sut" in
  go)
    go build -o "$work/oauth2-server" ./cmd/oauth2-server
    printf 'placeholder-key-material' >"$work/signing.key"
    chmod 600 "$work/signing.key"
    OAUTH2_ADDR="127.0.0.1:${port}" \
    OAUTH2_ENVIRONMENT=test \
    OAUTH2_ISSUER="$issuer" \
    OAUTH2_SIGNING_KEY_FILE="$work/signing.key" \
    OAUTH2_SESSION_SECRET=0123456789abcdef0123456789abcdef \
    OAUTH2_COOKIE_SECURE=false \
    OAUTH2_CONFORMANCE_MODE=1 \
    OAUTH2_CONFORMANCE_SEED="$work/seed.yaml" \
      "$work/oauth2-server" >"$work/server.log" 2>&1 &
    pid=$!
    ;;
  rust)
    [ -x "${RUST_SUT_BIN:-}" ] || { echo "SUT=rust needs RUST_SUT_BIN=/path/to/rust_oauth2_server" >&2; exit 1; }
    OAUTH2_CONFORMANCE_MODE=1 \
    OAUTH2_CONFORMANCE_SEED="$work/seed.yaml" \
    OAUTH2_ENV=test \
    OAUTH2_DATABASE_URL=sqlite::memory: \
    OAUTH2_JWT_SECRET="$(openssl rand -hex 32)" \
    OAUTH2_SESSION_KEY="$(openssl rand -hex 64)" \
    OAUTH2_SERVER_HOST=127.0.0.1 \
    OAUTH2_SERVER_PORT="$port" \
      "$RUST_SUT_BIN" >"$work/server.log" 2>&1 &
    pid=$!
    ;;
  *)
    echo "SUT must be go or rust (got $sut)" >&2
    exit 1
    ;;
esac

ready=0
for _ in $(seq 1 100); do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "FAIL: server exited before becoming ready; log:" >&2
    cat "$work/server.log" >&2
    exit 1
  fi
  if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.1
done
[ "$ready" -eq 1 ] || { echo "FAIL: server never became ready" >&2; cat "$work/server.log" >&2; exit 1; }

# One scenario tree: the contract's plus the supplementary ones.
mkdir -p "$work/scenarios/local"
cp -R "$contract_dir/scenarios/." "$work/scenarios/"
cp -R "$repo_root/conformance/scenarios/." "$work/scenarios/local/"

echo "== contract runner: core profile against the ${sut} server (port ${port}) =="
pnpm --dir "$contract_dir/runner" exec tsx src/cli.ts run \
  --base-url "http://127.0.0.1:${port}" \
  --scenarios "$work/scenarios" \
  --profile core \
  --implementation "${sut}-oauth2-server"

echo "== contract runner: token-lifecycle profile against the ${sut} server (port ${port}) =="
pnpm --dir "$contract_dir/runner" exec tsx src/cli.ts run \
  --base-url "http://127.0.0.1:${port}" \
  --scenarios "$work/scenarios" \
  --profile token-lifecycle \
  --implementation "${sut}-oauth2-server"

echo "== contract runner: oidc-basic profile against the ${sut} server (port ${port}) =="
pnpm --dir "$contract_dir/runner" exec tsx src/cli.ts run \
  --base-url "http://127.0.0.1:${port}" \
  --scenarios "$work/scenarios" \
  --profile oidc-basic \
  --implementation "${sut}-oauth2-server"
