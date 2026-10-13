#!/usr/bin/env bash
# SUT-free, deterministic self-test of the pinned shared conformance runner.
#
# Proves the runner wires scenario expectations into its exit status:
#   known match    -> exit 0
#   known mismatch -> exit 1 (conformance failure; 2 is a usage error and fails us)
#
# No Go server is involved. A throwaway stub answers one fixed request, and the
# scenario is read at run time from the pinned contract checkout, so this repo
# vendors no fixtures and contains no harness of its own.
#
# usage: scripts/contract-selftest.sh [CONTRACT_DIR]   (default: .contract)
set -euo pipefail

cd "$(dirname "$0")/.."
contract_dir="$(cd "${1:-.contract}" && pwd)"
pin="$(sed -n 's/^commit:[[:space:]]*//p' conformance-contract.yaml)"
printf '%s' "$pin" | grep -Eq '^[0-9a-f]{40}$' || { echo "conformance-contract.yaml needs a full 40-hex commit pin" >&2; exit 1; }
actual="$(git -C "$contract_dir" rev-parse HEAD)"
[ "$actual" = "$pin" ] || { echo "contract at $actual, pinned $pin" >&2; exit 1; }

work="$(mktemp -d)"
stub_pid=""
cleanup() { [ -n "$stub_pid" ] && kill "$stub_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

# The one contract scenario used: expects 400 {"error":"unsupported_grant_type"}.
mkdir -p "$work/scenarios/core/token"
cp "$contract_dir/scenarios/core/token/unsupported-grant-type.yaml" "$work/scenarios/core/token/"

# start_stub STATUS: serves STATUS with an unsupported_grant_type body; sets $base_url.
start_stub() {
  rm -f "$work/port"
  node -e '
    const http = require("node:http");
    const fs = require("node:fs");
    const [status, body, portFile] = [Number(process.argv[1]), process.argv[2], process.argv[3]];
    const srv = http.createServer((req, res) => {
      req.resume();
      res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(body);
    });
    srv.listen(0, "127.0.0.1", () => fs.writeFileSync(portFile, String(srv.address().port)));
  ' "$1" "$2" "$work/port" &
  stub_pid=$!
  for _ in $(seq 1 50); do [ -s "$work/port" ] && break; sleep 0.1; done
  [ -s "$work/port" ] || { echo "stub did not start" >&2; exit 1; }
  base_url="http://127.0.0.1:$(cat "$work/port")"
}
stop_stub() { kill "$stub_pid" 2>/dev/null || true; wait "$stub_pid" 2>/dev/null || true; stub_pid=""; }

run_runner() {
  pnpm --dir "$contract_dir/runner" exec tsx src/cli.ts run \
    --base-url "$base_url" --scenarios "$work/scenarios" --profile core
}

echo "== known match: stub answers 400 unsupported_grant_type, scenario expects same =="
start_stub 400 '{"error":"unsupported_grant_type"}'
set +e; run_runner; match_status=$?; set -e
stop_stub
[ "$match_status" -eq 0 ] || { echo "FAIL: known match exited $match_status, want 0" >&2; exit 1; }

echo "== known mismatch: stub answers 200, scenario expects 400 =="
start_stub 200 '{"error":"unsupported_grant_type"}'
set +e; run_runner; mismatch_status=$?; set -e
stop_stub
[ "$mismatch_status" -eq 1 ] || { echo "FAIL: known mismatch exited $mismatch_status, want 1" >&2; exit 1; }

echo "== known mismatch: stub answers 400 with the wrong error body =="
start_stub 400 '{"error":"invalid_request"}'
set +e; run_runner; body_status=$?; set -e
stop_stub
[ "$body_status" -eq 1 ] || { echo "FAIL: body mismatch exited $body_status, want 1" >&2; exit 1; }

echo "contract-selftest: OK (match=0, mismatch=1, body-mismatch=1)"
