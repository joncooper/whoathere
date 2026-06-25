#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-endpoint-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_ENDPOINT_SMOKE_TIMEOUT_SECONDS:-60}"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere endpoint smoke temp=%s\n' "$RUN_DIR"
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
        f"whoathere endpoint smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

run_cli_capture() {
  local output_path="$1"
  shift
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- "$@" >"$output_path" 2>&1
}

run_expected_deny() {
  local output_path="$1"
  shift
  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" "$@" >"$output_path" 2>&1
  local code="$?"
  set -e
  summarize_output "$output_path"
  printf 'whoathere endpoint smoke command_exit=%s\n' "$code"
  test "$code" -eq 20
}

summarize_output() {
  local output_path="$1"
  grep -E \
    '^(whoathere endpoint setup|whoathere protect|mode=|installed=|status=|provider_scope=|current_provider_platform=|ready_for_high_risk_execution=|source_scan_status=|launch_plan_status=|launch_plan_blocking_reason=|execution_reason=|exit_code=)' \
    "$output_path" || true
}

require_output() {
  local output_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$output_path"; then
    printf 'whoathere endpoint smoke missing expected output: %s\n' "$pattern" >&2
    printf 'whoathere endpoint smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

main() {
  local workspace shim_dir replay_store setup_output shim_output npm_output pip_output resolved_npm resolved_pip
  workspace="$RUN_DIR/workspace"
  shim_dir="$RUN_DIR/shims"
  replay_store="$RUN_DIR/replay-store.txt"
  setup_output="$RUN_DIR/endpoint-setup.out"
  shim_output="$RUN_DIR/shim-install.out"
  npm_output="$RUN_DIR/npm-ci.out"
  pip_output="$RUN_DIR/pip-install.out"

  mkdir -p "$workspace"
  printf 'registry=http://127.0.0.1:4873/npm/\n' >"$workspace/.npmrc"

  set +e
  run_cli_capture "$setup_output" endpoint setup \
    --shim-dir "$shim_dir" \
    --workspace "$workspace" \
    --vault-origin http://127.0.0.1:4873 \
    --replay-store "$replay_store"
  local setup_code="$?"
  set -e
  summarize_output "$setup_output"
  printf 'whoathere endpoint smoke setup_exit=%s\n' "$setup_code"
  test "$setup_code" -eq 20
  require_output "$setup_output" 'status=fail_closed'
  require_output "$setup_output" 'replay_store='
  require_output "$setup_output" 'export_WHOATHERE_REPLAY_STORE=export WHOATHERE_REPLAY_STORE='
  require_output "$setup_output" 'provider_check_command=whoathere evidence providers --json --require-ready --scope current'
  require_output "$setup_output" 'ready_for_high_risk_execution=false'

  run_cli_capture "$shim_output" shim install --dest "$shim_dir"
  summarize_output "$shim_output"
  require_output "$shim_output" 'mode=materialize'
  require_output "$shim_output" 'installed=4'
  grep -q 'protect --execute npm --' "$shim_dir/npm"
  grep -q 'protect --execute pip --' "$shim_dir/pip"

  resolved_npm="$(PATH="$shim_dir:$PATH" command -v npm)"
  resolved_pip="$(PATH="$shim_dir:$PATH" command -v pip)"
  test "$resolved_npm" = "$shim_dir/npm"
  test "$resolved_pip" = "$shim_dir/pip"

  (
    cd "$workspace"
    run_expected_deny "$npm_output" env \
      WHOATHERE_WORKSPACE="$workspace" \
      WHOATHERE_VAULT_ORIGIN=http://127.0.0.1:4873 \
      WHOATHERE_REPLAY_STORE="$replay_store" \
      PATH="$shim_dir:$PATH" \
      npm ci
  )
  require_output "$npm_output" 'whoathere protect'
  require_output "$npm_output" 'source_scan_status=ok'
  require_output "$npm_output" 'launch_plan_status=blocked'
  require_output "$npm_output" 'egress_verified_proof_required'
  require_output "$npm_output" 'execution_reason=launch_plan_blocked'

  (
    cd "$workspace"
    run_expected_deny "$pip_output" env \
      WHOATHERE_WORKSPACE="$workspace" \
      WHOATHERE_VAULT_ORIGIN=http://127.0.0.1:4873 \
      WHOATHERE_REPLAY_STORE="$replay_store" \
      PATH="$shim_dir:$PATH" \
      pip install fixture
  )
  require_output "$pip_output" 'whoathere protect'
  require_output "$pip_output" 'launch_plan_status=blocked'
  require_output "$pip_output" 'egress_verified_proof_required'
  require_output "$pip_output" 'execution_reason=launch_plan_blocked'

  if [[ -d "$workspace/node_modules" ]]; then
    printf 'whoathere endpoint smoke npm unexpectedly created node_modules\n' >&2
    return 1
  fi

  printf 'whoathere endpoint smoke ok\n'
}

main "$@"
