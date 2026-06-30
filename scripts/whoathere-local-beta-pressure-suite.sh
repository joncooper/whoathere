#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK_DIR="${TMPDIR:-/tmp}/whoathere-local-beta-pressure-suite.$$"
LOG_DIR="$WORK_DIR/logs"

cleanup() {
  if [ "${WHOATHERE_KEEP_PRESSURE_LOGS:-0}" = "1" ]; then
    printf 'pressure_suite_log_dir=%s\n' "$LOG_DIR"
  else
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT INT TERM

mkdir -p "$LOG_DIR"

run_step() {
  name=$1
  shift
  log="$LOG_DIR/$name.log"
  started=$(date +%s)
  printf 'pressure_step_start=%s\n' "$name"
  set +e
  "$@" >"$log" 2>&1
  status=$?
  set -e
  ended=$(date +%s)
  elapsed=$((ended - started))
  if [ "$status" -ne 0 ]; then
    printf 'pressure_step=%s status=failed exit_code=%s elapsed_seconds=%s log=%s\n' "$name" "$status" "$elapsed" "$log" >&2
    cat "$log" >&2
    exit "$status"
  fi
  printf 'pressure_step=%s status=ok elapsed_seconds=%s log=%s\n' "$name" "$elapsed" "$log"
}

main() {
  suite_started=$(date +%s)
  run_step package_risk_smoke "$ROOT_DIR/scripts/whoathere-package-risk-smoke.sh"
  run_step real_world_attack_harness "$ROOT_DIR/scripts/whoathere-real-world-attack-harness.sh"
  run_step local_beta_pressure_smoke "$ROOT_DIR/scripts/whoathere-local-beta-pressure-smoke.sh"
  if [ "${WHOATHERE_PRESSURE_SKIP_COMPAT:-0}" = "1" ]; then
    printf 'pressure_step=compat_smoke status=skipped reason=WHOATHERE_PRESSURE_SKIP_COMPAT\n'
  else
    run_step compat_smoke "$ROOT_DIR/scripts/whoathere-compat-smoke.sh"
  fi
  if [ "${WHOATHERE_PRESSURE_ENABLE_VM:-0}" = "1" ]; then
    if [ -z "${WHOATHERE_PRESSURE_RUNTIME_ARCHIVE:-}" ]; then
      printf 'pressure_step=runtime_qualification status=failed reason=WHOATHERE_PRESSURE_RUNTIME_ARCHIVE_required\n' >&2
      exit 64
    fi
    if [ -n "${WHOATHERE_PRESSURE_RUNTIME_STATE_DIR:-}" ]; then
      run_step runtime_qualification \
        "$ROOT_DIR/scripts/whoathere-runtime-qualification.sh" \
        --archive "$WHOATHERE_PRESSURE_RUNTIME_ARCHIVE" \
        --state-dir "$WHOATHERE_PRESSURE_RUNTIME_STATE_DIR"
    else
      run_step runtime_qualification \
        "$ROOT_DIR/scripts/whoathere-runtime-qualification.sh" \
        --archive "$WHOATHERE_PRESSURE_RUNTIME_ARCHIVE"
    fi
  else
    printf 'pressure_step=runtime_qualification status=skipped reason=WHOATHERE_PRESSURE_ENABLE_VM\n'
  fi
  suite_ended=$(date +%s)
  printf 'local_beta_pressure_suite=ok elapsed_seconds=%s\n' "$((suite_ended - suite_started))"
}

main "$@"
