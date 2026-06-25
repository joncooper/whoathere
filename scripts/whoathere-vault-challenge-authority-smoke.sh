#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-vault-challenge-authority-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_VAULT_CHALLENGE_AUTHORITY_SMOKE_TIMEOUT_SECONDS:-60}"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere vault challenge authority smoke temp=%s\n' "$RUN_DIR"
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
        f"whoathere vault challenge authority smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

require_output() {
  local output_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$output_path"; then
    printf 'whoathere vault challenge authority smoke missing expected output: %s\n' "$pattern" >&2
    printf 'whoathere vault challenge authority smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

reject_output() {
  local output_path="$1"
  local pattern="$2"
  if grep -q "$pattern" "$output_path"; then
    printf 'whoathere vault challenge authority smoke found forbidden output: %s\n' "$pattern" >&2
    printf 'whoathere vault challenge authority smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

run_case() {
  local name="$1"
  local expected_code="$2"
  shift 2
  local output_path="$RUN_DIR/${name}.txt"

  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    vault challenge-sim "$@" >"$output_path" 2>&1
  local code="$?"
  set -e

  printf 'whoathere vault challenge authority smoke case=%s command_exit=%s\n' "$name" "$code"
  test "$code" -eq "$expected_code"
  require_output "$output_path" 'whoathere vault challenge-sim'
  require_output "$output_path" '"authority":"vault_challenge_authority.v1"'
  require_output "$output_path" '"trusted_time_source":"vault_server_clock"'
  require_output "$output_path" '"client_time_accepted":false'
  require_output "$output_path" '"raw_nonce_returned":false'
  reject_output "$output_path" 'proof-nonce-'
}

main() {
  run_case accepted 0
  require_output "$RUN_DIR/accepted.txt" 'status_code=200'
  require_output "$RUN_DIR/accepted.txt" '"first_consume_status":"Accepted"'
  require_output "$RUN_DIR/accepted.txt" '"accepted":true'

  run_case replay 20 --replay
  require_output "$RUN_DIR/replay.txt" 'status_code=409'
  require_output "$RUN_DIR/replay.txt" 'provider_challenge_replayed'

  run_case unknown 20 --unknown-challenge
  require_output "$RUN_DIR/unknown.txt" 'provider_challenge_not_issued'

  run_case tampered 20 --mutate-context
  require_output "$RUN_DIR/tampered.txt" 'provider_challenge_context_mutated'

  run_case expired 20 --expired
  require_output "$RUN_DIR/expired.txt" 'provider_challenge_expired'

  printf 'whoathere vault challenge authority smoke ok\n'
}

main "$@"
