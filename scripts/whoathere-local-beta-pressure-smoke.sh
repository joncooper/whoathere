#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLI="$ROOT_DIR/whoathere/target/debug/whoathere"
WORK_DIR="${TMPDIR:-/tmp}/whoathere-local-beta-pressure.$$"
STATE_DIR="$WORK_DIR/state"
SCANNER_CACHE="$WORK_DIR/scanners"
SCANNER_BIN="$SCANNER_CACHE/bin"
WHOATHERE_SCANNER_CACHE_DIR="$SCANNER_CACHE"
export WHOATHERE_SCANNER_CACHE_DIR

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

require_contains() {
  needle=$1
  file=$2
  label=$3
  if ! grep -Fq "$needle" "$file"; then
    echo "missing_${label}: $needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

require_not_contains() {
  needle=$1
  file=$2
  label=$3
  if grep -Fq "$needle" "$file"; then
    echo "forbidden_${label}: $needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

run_capture() {
  expected=$1
  output=$2
  shift 2
  set +e
  "$@" >"$output" 2>&1
  status=$?
  set -e
  if [ "$status" -ne "$expected" ]; then
    echo "unexpected_exit expected=$expected actual=$status command=$*" >&2
    cat "$output" >&2
    exit 1
  fi
}

receipt_path_from_output() {
  sed -n 's/.*"receipt_path": "\([^"]*\)".*/\1/p' "$1" | head -n 1
}

write_fake_scanners() {
  mkdir -p "$SCANNER_BIN"
  for scanner in guarddog osv-scanner pip-audit syft grype trivy scorecard; do
    cat >"$SCANNER_BIN/$scanner" <<'SH'
#!/bin/sh
printf '{"findings":[]}\n'
exit 0
SH
    chmod +x "$SCANNER_BIN/$scanner"
  done
}

write_scanner_receipt() {
  workspace=$1
  ecosystem=$2
  output=$3
  run_capture 0 "$output" "$CLI" scanners run \
    --workspace "$workspace" \
    --ecosystem "$ecosystem" \
    --state-dir "$STATE_DIR" \
    --execute \
    --json
  require_contains '"scanner_clean": true' "$output" scanner_clean
  require_contains '"scanner_receipt_auth"' "$output" scanner_auth
}

cargo build --manifest-path "$ROOT_DIR/whoathere/Cargo.toml" -p whoathere-cli --bin whoathere >/dev/null
mkdir -p "$WORK_DIR"
write_fake_scanners

NPM_CLEAN="$WORK_DIR/npm-clean-app"
mkdir -p "$NPM_CLEAN"
cat >"$NPM_CLEAN/package.json" <<'JSON'
{
  "name": "npm-clean-pressure-app",
  "version": "1.0.0",
  "whoatherePublishedAtUnixSeconds": 1700000000,
  "private": true,
  "scripts": {
    "test": "node -e \"process.exit(0)\""
  }
}
JSON
cat >"$NPM_CLEAN/package-lock.json" <<'JSON'
{
  "name": "npm-clean-pressure-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "npm-clean-pressure-app",
      "version": "1.0.0"
    }
  }
}
JSON
write_scanner_receipt "$NPM_CLEAN" npm "$WORK_DIR/npm-clean-scanner.json"
run_capture 0 "$WORK_DIR/npm-clean-risk.json" "$CLI" package-risk assess \
  --workspace "$NPM_CLEAN" \
  --ecosystem npm \
  --state-dir "$STATE_DIR" \
  --scanner-receipt "$WORK_DIR/npm-clean-scanner.json" \
  --json
require_contains '"overall_verdict": "auto_sync_candidate"' "$WORK_DIR/npm-clean-risk.json" npm_clean_auto
require_contains '"decision_summary"' "$WORK_DIR/npm-clean-risk.json" npm_clean_summary
require_contains '"host_effect": "assessment_only_no_package_code_executed_no_project_files_copied_receipt_and_local_memory_may_be_written"' "$WORK_DIR/npm-clean-risk.json" npm_clean_host_effect
require_contains 'Use this receipt with whoathere vm release-plan' "$WORK_DIR/npm-clean-risk.json" npm_clean_action

NPM_WORKSPACE_LOCAL="$WORK_DIR/npm-workspace-local"
mkdir -p "$NPM_WORKSPACE_LOCAL/packages/internal-tool"
cat >"$NPM_WORKSPACE_LOCAL/package.json" <<'JSON'
{
  "name": "npm-workspace-pressure-app",
  "version": "1.0.0",
  "whoatherePublishedAtUnixSeconds": 1700000000,
  "repository": "https://example.invalid/npm-workspace-pressure-app",
  "workspaces": ["packages/*"],
  "dependencies": {
    "internal-tool": "file:packages/internal-tool"
  }
}
JSON
cat >"$NPM_WORKSPACE_LOCAL/packages/internal-tool/package.json" <<'JSON'
{"name":"internal-tool","version":"1.0.0"}
JSON
write_scanner_receipt "$NPM_WORKSPACE_LOCAL" npm "$WORK_DIR/npm-workspace-scanner.json"
run_capture 20 "$WORK_DIR/npm-workspace-risk.json" "$CLI" package-risk assess \
  --workspace "$NPM_WORKSPACE_LOCAL" \
  --ecosystem npm \
  --state-dir "$STATE_DIR" \
  --scanner-receipt "$WORK_DIR/npm-workspace-scanner.json" \
  --json
require_contains '"overall_verdict": "deny"' "$WORK_DIR/npm-workspace-risk.json" npm_workspace_deny
require_contains 'dependency_source_local' "$WORK_DIR/npm-workspace-risk.json" npm_workspace_local
require_contains 'Replace direct, VCS, editable, or local dependencies with pinned registry artifacts' "$WORK_DIR/npm-workspace-risk.json" npm_workspace_action
require_contains 'Package code was not run on the host' "$WORK_DIR/npm-workspace-risk.json" npm_workspace_summary

PIP_PINNED="$WORK_DIR/pip-pinned"
mkdir -p "$PIP_PINNED"
cat >"$PIP_PINNED/requirements.txt" <<'REQ'
requests==2.31.0 # whoathere-published-at=1700000000
REQ
write_scanner_receipt "$PIP_PINNED" pypi "$WORK_DIR/pip-pinned-scanner.json"
run_capture 0 "$WORK_DIR/pip-pinned-risk.json" "$CLI" package-risk assess \
  --workspace "$PIP_PINNED" \
  --ecosystem pypi \
  --state-dir "$STATE_DIR" \
  --scanner-receipt "$WORK_DIR/pip-pinned-scanner.json" \
  --json
require_contains '"overall_verdict": "auto_sync_candidate"' "$WORK_DIR/pip-pinned-risk.json" pip_pinned_auto
PIP_PINNED_RECEIPT=$(receipt_path_from_output "$WORK_DIR/pip-pinned-risk.json")
run_capture 0 "$WORK_DIR/pip-pinned-approve.json" "$CLI" package-risk approve \
  --receipt "$PIP_PINNED_RECEIPT" \
  --reason "local beta pressure smoke pinned pip baseline" \
  --state-dir "$STATE_DIR" \
  --json

UV_PINNED="$WORK_DIR/uv-pinned"
mkdir -p "$UV_PINNED"
cat >"$UV_PINNED/requirements.txt" <<'REQ'
uv-safe==2.3.4 # whoathere-published-at=1700000000
REQ
write_scanner_receipt "$UV_PINNED" pypi "$WORK_DIR/uv-pinned-scanner.json"
run_capture 0 "$WORK_DIR/uv-pinned-risk.json" "$CLI" package-risk assess \
  --workspace "$UV_PINNED" \
  --ecosystem uv \
  --state-dir "$STATE_DIR" \
  --scanner-receipt "$WORK_DIR/uv-pinned-scanner.json" \
  --json
UV_PINNED_RECEIPT=$(receipt_path_from_output "$WORK_DIR/uv-pinned-risk.json")
run_capture 0 "$WORK_DIR/uv-pinned-approve.json" "$CLI" package-risk approve \
  --receipt "$UV_PINNED_RECEIPT" \
  --reason "local beta pressure smoke uv baseline" \
  --state-dir "$STATE_DIR" \
  --json

UV_RANGE="$WORK_DIR/uv-range"
mkdir -p "$UV_RANGE"
cat >"$UV_RANGE/requirements.txt" <<'REQ'
uv-safe>=2.0
REQ
write_scanner_receipt "$UV_RANGE" pypi "$WORK_DIR/uv-range-scanner.json"
run_capture 0 "$WORK_DIR/uv-range-risk.json" "$CLI" package-risk assess \
  --workspace "$UV_RANGE" \
  --ecosystem uv \
  --state-dir "$STATE_DIR" \
  --scanner-receipt "$WORK_DIR/uv-range-scanner.json" \
  --json
require_contains 'last_known_good_substitution_selected' "$WORK_DIR/uv-range-risk.json" uv_lkg
require_contains '"selected_version": "2.3.4"' "$WORK_DIR/uv-range-risk.json" uv_selected
require_contains 'Use the selected last-known-good version instead of silently upgrading the unpinned request' "$WORK_DIR/uv-range-risk.json" uv_action

for file in "$WORK_DIR"/*.json; do
  require_not_contains 'NPM_TOKEN=' "$file" raw_npm_token
  require_not_contains 'PYPI_TOKEN=' "$file" raw_pypi_token
  require_not_contains '/Users/' "$file" raw_host_path
done

echo "local_beta_pressure_smoke=ok"
