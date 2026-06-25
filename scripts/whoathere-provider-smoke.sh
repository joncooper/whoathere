#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-provider-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_PROVIDER_SMOKE_TIMEOUT_SECONDS:-60}"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere provider smoke temp=%s\n' "$RUN_DIR"
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
        f"whoathere provider smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

require_output() {
  local output_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$output_path"; then
    printf 'whoathere provider smoke missing expected output: %s\n' "$pattern" >&2
    printf 'whoathere provider smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

main() {
  local output_path code
  output_path="$RUN_DIR/evidence-providers-current.json"

  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    evidence providers --json --require-ready --scope current >"$output_path" 2>&1
  code="$?"
  set -e

  grep -E '"(provider_scope|current_provider_platform|provider_ready|status|exit_code|target_matches_host|proof_verification_enabled|can_verify_now|active_verification_enabled|package_execution_attempted|os_mutation_attempted|network_mutation_attempted|public_network_probe_attempted)"' "$output_path" || true
  printf 'whoathere provider smoke command_exit=%s\n' "$code"

  test "$code" -eq 20
  require_output "$output_path" '"provider_scope": "current"'
  require_output "$output_path" '"provider_ready": false'
  require_output "$output_path" '"status": "fail_closed"'
  require_output "$output_path" '"exit_code": 20'
  require_output "$output_path" '"target_matches_host": true'
  require_output "$output_path" '"active_verification_enabled": false'
  require_output "$output_path" '"package_execution_attempted": false'
  require_output "$output_path" '"os_mutation_attempted": false'
  require_output "$output_path" '"network_mutation_attempted": false'
  require_output "$output_path" '"public_network_probe_attempted": false'
  require_output "$output_path" '"proof_verification_enabled": false'
  require_output "$output_path" '"can_verify_now": false'

  printf 'whoathere provider smoke ok\n'
}

main "$@"
