#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-provider-challenge-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_PROVIDER_CHALLENGE_SMOKE_TIMEOUT_SECONDS:-60}"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere provider challenge smoke temp=%s\n' "$RUN_DIR"
  fi
}
trap cleanup EXIT

run_with_timeout() {
  local seconds="$1"
  shift
  python3 - "$seconds" "$@" <<'PY'
import shlex
import subprocess
import sys

timeout = float(sys.argv[1])
command = sys.argv[2:]
try:
    raise SystemExit(subprocess.run(command, timeout=timeout).returncode)
except subprocess.TimeoutExpired:
    printable = " ".join(shlex.quote(part) for part in command)
    print(
        f"whoathere provider challenge smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

require_output() {
  local output_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$output_path"; then
    printf 'whoathere provider challenge smoke missing expected output: %s\n' "$pattern" >&2
    printf 'whoathere provider challenge smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

main() {
  local output_path code
  output_path="$RUN_DIR/evidence-challenge-current.json"

  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    evidence challenge --json --scope current \
    --subject launch-sha256-smoke \
    --context-hash sha256:smoke-context \
    --vault-host 127.0.0.1:4873 >"$output_path" 2>&1
  code="$?"
  set -e

  grep -E '"(command|provider_scope|provider|mutation|status|exit_code|challenge_id|valid|satisfied|containment_status|egress_status)"' "$output_path" || true
  printf 'whoathere provider challenge smoke command_exit=%s\n' "$code"

  test "$code" -eq 20
  require_output "$output_path" '"command": "whoathere evidence challenge"'
  require_output "$output_path" '"provider_scope": "current"'
  require_output "$output_path" '"mutation": false'
  require_output "$output_path" '"status": "fail_closed"'
  require_output "$output_path" '"exit_code": 20'
  require_output "$output_path" '"subject": "launch-sha256-smoke"'
  require_output "$output_path" '"context_hash": "sha256:smoke-context"'
  require_output "$output_path" '"configured_vault_host": "127.0.0.1:4873"'
  require_output "$output_path" '"valid": true'
  require_output "$output_path" '"satisfied": false'
  require_output "$output_path" 'provider_challenge_egress_probe_missing'
  require_output "$output_path" 'provider_challenge_proof_not_fresh'

  printf 'whoathere provider challenge smoke ok\n'
}

main "$@"
