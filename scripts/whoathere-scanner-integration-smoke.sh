#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WHOATHERE_BIN=${WHOATHERE_BIN:-"$ROOT_DIR/whoathere/target/debug/whoathere"}
ORIGINAL_PATH=${PATH:-}

cargo build --manifest-path "$ROOT_DIR/whoathere/Cargo.toml" -p whoathere-cli --bin whoathere >/dev/null

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-scanner-smoke.XXXXXX")
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

FAKE_BIN="$WORK_DIR/fake-bin"
mkdir -p "$FAKE_BIN"

write_fake_scanner() {
  name=$1
  cat > "$FAKE_BIN/$name" <<'EOF'
#!/bin/sh
case "$*" in
  *timeout-npm*) sleep 3; printf '{"findings":[]}\n' ;;
  *bad-npm*) printf '{"findings":[{"whoathere_fake_finding":true}]}\n' ;;
  *) printf '{"findings":[]}\n' ;;
esac
exit 0
EOF
  chmod +x "$FAKE_BIN/$name"
}

for scanner in guarddog osv-scanner pip-audit syft grype trivy scorecard; do
  write_fake_scanner "$scanner"
done

write_clean_npm() {
  dir=$1
  mkdir -p "$dir"
  cat > "$dir/package.json" <<'JSON'
{"name":"whoathere-clean","version":"0.0.1","dependencies":{}}
JSON
  printf "module.exports = 1;\n" > "$dir/index.js"
}

write_python_requirements() {
  dir=$1
  requirements=$2
  mkdir -p "$dir"
  printf '%s\n' "$requirements" > "$dir/requirements.txt"
}

require_contains() {
  needle=$1
  file=$2
  reason=$3
  if ! grep -Fq "$needle" "$file"; then
    printf 'scanner_smoke_failed=%s\n' "$reason" >&2
    printf 'missing=%s\n' "$needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

require_not_contains() {
  needle=$1
  file=$2
  reason=$3
  if grep -Fq "$needle" "$file"; then
    printf 'scanner_smoke_failed=%s\n' "$reason" >&2
    printf 'forbidden=%s\n' "$needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

PATH="$FAKE_BIN:$ORIGINAL_PATH"
export PATH

"$WHOATHERE_BIN" scanners list --json > "$WORK_DIR/list.json"
require_contains '"command": "whoathere scanners list"' "$WORK_DIR/list.json" list_json_missing
require_contains '"scanner_public_package_auto_trust_ready"' "$WORK_DIR/list.json" list_ready_field_missing

"$WHOATHERE_BIN" scanners bootstrap-plan --json > "$WORK_DIR/bootstrap-plan.json"
require_contains '"command": "whoathere scanners bootstrap-plan"' "$WORK_DIR/bootstrap-plan.json" bootstrap_plan_missing
require_contains 'scripts/whoathere-bootstrap-scanners.sh' "$WORK_DIR/bootstrap-plan.json" bootstrap_script_missing

CLEAN_NPM="$WORK_DIR/clean-npm"
BAD_NPM="$WORK_DIR/bad-npm"
TIMEOUT_NPM="$WORK_DIR/timeout-npm"
UNPINNED_PY="$WORK_DIR/unpinned-py"
write_clean_npm "$CLEAN_NPM"
write_clean_npm "$BAD_NPM"
write_clean_npm "$TIMEOUT_NPM"
write_python_requirements "$UNPINNED_PY" "requests"

"$WHOATHERE_BIN" scanners run --workspace "$CLEAN_NPM" --ecosystem npm --execute --json > "$WORK_DIR/clean.json"
require_contains '"scanner_clean": true' "$WORK_DIR/clean.json" clean_not_clean
require_contains '"status": "passed"' "$WORK_DIR/clean.json" clean_pass_status_missing
require_not_contains "$WORK_DIR" "$WORK_DIR/clean.json" clean_leaked_workspace_path
require_not_contains 'WHOATHERE_CANARY_TOKEN' "$WORK_DIR/clean.json" clean_leaked_canary
require_not_contains 'NPM_TOKEN' "$WORK_DIR/clean.json" clean_leaked_token

if "$WHOATHERE_BIN" scanners run --workspace "$BAD_NPM" --ecosystem npm --execute --json > "$WORK_DIR/bad.json"; then
  printf 'scanner_smoke_failed=bad_fixture_unexpected_success\n' >&2
  cat "$WORK_DIR/bad.json" >&2
  exit 1
fi
require_contains '"scanner_clean": false' "$WORK_DIR/bad.json" bad_not_blocked
require_contains '"status": "findings"' "$WORK_DIR/bad.json" bad_findings_missing
require_contains 'scanner_findings_observed' "$WORK_DIR/bad.json" bad_reason_missing
require_not_contains "$WORK_DIR" "$WORK_DIR/bad.json" bad_leaked_workspace_path

"$WHOATHERE_BIN" scanners run --workspace "$UNPINNED_PY" --ecosystem pypi --execute --json > "$WORK_DIR/unpinned.json" || true
require_contains 'pip_audit_unpinned_requirement_skipped' "$WORK_DIR/unpinned.json" unpinned_skip_missing

if "$WHOATHERE_BIN" scanners run --workspace "$TIMEOUT_NPM" --ecosystem npm --timeout-seconds 1 --execute --json > "$WORK_DIR/timeout.json"; then
  printf 'scanner_smoke_failed=timeout_fixture_unexpected_success\n' >&2
  cat "$WORK_DIR/timeout.json" >&2
  exit 1
fi
require_contains '"status": "timed_out"' "$WORK_DIR/timeout.json" timeout_status_missing
require_contains 'scanner_process_timed_out' "$WORK_DIR/timeout.json" timeout_reason_missing

if [ "${WHOATHERE_SCANNER_REAL_SMOKE:-0}" = "1" ]; then
  REAL_PATH="$ROOT_DIR/.whoathere/scanners/bin:$ORIGINAL_PATH"
  PATH="$REAL_PATH" "$WHOATHERE_BIN" scanners run --workspace "$CLEAN_NPM" --ecosystem npm --execute --json > "$WORK_DIR/real-clean.json" || true
  require_contains '"command": "whoathere scanners run"' "$WORK_DIR/real-clean.json" real_smoke_no_output
fi

printf 'scanner_integration_smoke=ok\n'
printf 'work_dir=%s\n' "$WORK_DIR"
