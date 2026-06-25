#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-linux-active-probe-fixture-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_LINUX_ACTIVE_PROBE_FIXTURE_SMOKE_TIMEOUT_SECONDS:-60}"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere linux active probe fixture smoke temp=%s\n' "$RUN_DIR"
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
        f"whoathere linux active probe fixture smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

require_output() {
  local output_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$output_path"; then
    printf 'whoathere linux active probe fixture smoke missing expected output: %s\n' "$pattern" >&2
    printf 'whoathere linux active probe fixture smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

run_fixture() {
  local profile="$1"
  local output_path="$2"
  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    evidence linux-active-probe-fixture --json \
    --subject launch-sha256-smoke \
    --context-hash sha256:smoke-context \
    --vault-host 127.0.0.1:4873 \
    --profile "$profile" >"$output_path" 2>&1
  local code="$?"
  set -e
  printf '%s\n' "$code"
}

main() {
  local complete_path overpermissive_path incomplete_path complete_code overpermissive_code incomplete_code
  complete_path="$RUN_DIR/complete.json"
  overpermissive_path="$RUN_DIR/overpermissive.json"
  incomplete_path="$RUN_DIR/incomplete.json"

  complete_code="$(run_fixture complete "$complete_path")"
  overpermissive_code="$(run_fixture overpermissive "$overpermissive_path")"
  incomplete_code="$(run_fixture incomplete "$incomplete_path")"

  grep -E '"(command|profile|status|exit_code|authorization|proof_minted|execution_allowed|satisfied)"' "$complete_path" || true
  printf 'whoathere linux active probe fixture smoke complete_exit=%s\n' "$complete_code"
  printf 'whoathere linux active probe fixture smoke overpermissive_exit=%s\n' "$overpermissive_code"
  printf 'whoathere linux active probe fixture smoke incomplete_exit=%s\n' "$incomplete_code"

  test "$complete_code" -eq 0
  require_output "$complete_path" '"command": "whoathere evidence linux-active-probe-fixture"'
  require_output "$complete_path" '"profile": "complete"'
  require_output "$complete_path" '"status": "ok"'
  require_output "$complete_path" '"authorization": false'
  require_output "$complete_path" '"proof_minted": false'
  require_output "$complete_path" '"execution_allowed": false'
  require_output "$complete_path" '"satisfied": true'
  require_output "$complete_path" '"reason_codes": \[\]'

  test "$overpermissive_code" -eq 20
  require_output "$overpermissive_path" '"profile": "overpermissive"'
  require_output "$overpermissive_path" '"status": "fail_closed"'
  require_output "$overpermissive_path" '"satisfied": false'
  require_output "$overpermissive_path" 'linux_active_probe_non_vault_probe_allowed'

  test "$incomplete_code" -eq 20
  require_output "$incomplete_path" '"profile": "incomplete"'
  require_output "$incomplete_path" '"status": "fail_closed"'
  require_output "$incomplete_path" '"satisfied": false'
  require_output "$incomplete_path" 'linux_active_probe_not_complete'
  require_output "$incomplete_path" 'linux_active_probe_denied_probe_missing'

  printf 'whoathere linux active probe fixture smoke ok\n'
}

main "$@"
