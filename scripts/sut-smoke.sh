#!/usr/bin/env bash
# Black-box smoke test of the real oauth2-server binary: startup, readiness and
# fail-closed configuration. It exercises what unit tests cannot: process exit
# status and the shipped main wiring.
#
# This is NOT a conformance run. The skeleton implements no grant endpoints, so
# no contract profile is claimed or executed here.
#
# usage: scripts/sut-smoke.sh
set -euo pipefail

cd "$(dirname "$0")/.."
work="$(mktemp -d)"
pid=""
cleanup() {
  if [ -n "$pid" ]; then kill "$pid" 2>/dev/null || true; fi
  # mktemp -d output is ours alone; remove it with find to stay explicit.
  find "$work" -mindepth 1 -delete 2>/dev/null || true
  rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT

# Ask the kernel for a free port so a stray listener can never answer for us.
port="${SMOKE_PORT:-$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}"
bin="$work/oauth2-server"
go build -o "$bin" ./cmd/oauth2-server

printf 'placeholder-key-material' >"$work/signing.key"
chmod 600 "$work/signing.key"
cat >"$work/seed.yaml" <<YAML
issuer: http://localhost:$port
clients:
  - client_id: client-a
    client_secret: test-only-secret
    token_endpoint_auth_method: client_secret_basic
    redirect_uris: [https://client.example/callback]
users:
  - username: alice
    password: test-only-password
YAML

export OAUTH2_ISSUER="http://localhost:$port"
export OAUTH2_SIGNING_KEY_FILE="$work/signing.key"
export OAUTH2_SESSION_SECRET=0123456789abcdef0123456789abcdef

# expect_refusal NAME ENV...: the binary must exit nonzero under that env.
expect_refusal() {
  local name="$1"; shift
  local status
  set +e
  env "$@" "$bin" >"$work/refusal.log" 2>&1
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "FAIL: $name: server started, want refusal" >&2
    exit 1
  fi
  echo "ok: refused ($name)"
}

echo "== negative config: the process must exit nonzero =="
expect_refusal "missing issuer" -u OAUTH2_ISSUER
expect_refusal "missing signing key" -u OAUTH2_SIGNING_KEY_FILE
expect_refusal "short session secret" OAUTH2_SESSION_SECRET=short
expect_refusal "production over http" OAUTH2_ENVIRONMENT=production OAUTH2_STORAGE_DSN="$work/p.db"
expect_refusal "production in-memory storage" OAUTH2_ENVIRONMENT=production OAUTH2_ISSUER=https://auth.example.com
expect_refusal "conformance mode without a seed" OAUTH2_CONFORMANCE_MODE=1
expect_refusal "conformance mode in production" OAUTH2_ENVIRONMENT=production OAUTH2_ISSUER=https://auth.example.com \
  OAUTH2_STORAGE_DSN="$work/p.db" OAUTH2_CONFORMANCE_MODE=1 OAUTH2_CONFORMANCE_SEED="$work/seed.yaml"

wait_ready() {
  for _ in $(seq 1 50); do
    # The server we started must still be alive, or a health answer could come
    # from some other process already bound to the port.
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "FAIL: server exited before becoming ready; log:" >&2
      cat "$work/log" >&2
      exit 1
    fi
    if curl -fsS "http://127.0.0.1:$port/health" >"$work/health.json" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  echo "FAIL: server never became ready; log:" >&2; cat "$work/log" >&2
  exit 1
}

echo "== normal start: ready, no test-mode surface =="
OAUTH2_ADDR="127.0.0.1:$port" "$bin" >"$work/log" 2>&1 &
pid=$!
wait_ready
grep -q '"status":"ok"' "$work/health.json" || { echo "FAIL: /health body: $(cat "$work/health.json")" >&2; exit 1; }
if grep -q conformance "$work/health.json"; then echo "FAIL: test-mode detail exposed in normal mode" >&2; exit 1; fi
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/oauth/token")"
if [ "$code" != 404 ] && [ "$code" != 405 ]; then
  echo "FAIL: /oauth/token answered $code; no grant flow exists yet" >&2
  exit 1
fi
kill "$pid"
wait "$pid" 2>/dev/null || true
pid=""

echo "== conformance mode: seed applied before ready =="
OAUTH2_ADDR="127.0.0.1:$port" OAUTH2_CONFORMANCE_MODE=1 OAUTH2_CONFORMANCE_SEED="$work/seed.yaml" "$bin" >"$work/log" 2>&1 &
pid=$!
wait_ready
grep -q '"conformance":true' "$work/health.json" || { echo "FAIL: /health body: $(cat "$work/health.json")" >&2; exit 1; }
if grep -q 'test-only-secret\|test-only-password' "$work/log"; then echo "FAIL: seeded credentials in logs" >&2; exit 1; fi
kill -TERM "$pid"
set +e
wait "$pid"
status=$?
set -e
pid=""
[ "$status" -eq 0 ] || { echo "FAIL: graceful shutdown exited $status, want 0" >&2; exit 1; }

echo "sut-smoke: OK"
