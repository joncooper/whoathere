#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
PACKAGE_ROOT=$(CDPATH= cd -- "$HELPER_ROOT/../.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$HELPER_ROOT/../../.." && pwd)
RUST_WORKSPACE="$REPO_ROOT/whoathere"
. "$SCRIPT_DIR/provision-command-lib.sh"

if [ -x "$PACKAGE_ROOT/bin/whoathere" ]; then
  DEFAULT_WHOATHERE_BIN="$PACKAGE_ROOT/bin/whoathere"
elif [ -x "$RUST_WORKSPACE/target/debug/whoathere" ]; then
  DEFAULT_WHOATHERE_BIN="$RUST_WORKSPACE/target/debug/whoathere"
else
  DEFAULT_WHOATHERE_BIN="$REPO_ROOT/target/debug/whoathere"
fi

WHOATHERE_BIN=${WHOATHERE_BIN:-"$DEFAULT_WHOATHERE_BIN"}
HELPER=$(whoathere_default_helper_path "$HELPER_ROOT")
STATE_DIR=${WHOATHERE_VM_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}
WORK_ROOT=${TMPDIR:-/tmp}/whoathere-npm-uv-detonation.$$
RELEASE_VALIDATION_RECEIPT="$STATE_DIR/bundle/release-validation.json"
HEALTH_ATTEMPTS=${WHOATHERE_VM_HEALTH_ATTEMPTS:-30}
HEALTH_INTERVAL_SECONDS=${WHOATHERE_VM_HEALTH_INTERVAL_SECONDS:-10}
STARTED_BY_SCRIPT=0
HEALTH_OUTPUT=""

cleanup() {
  if [ "$STARTED_BY_SCRIPT" -eq 1 ]; then
    "$WHOATHERE_BIN" vm suspend --state-dir "$STATE_DIR" --helper "$HELPER" --execute >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_ROOT"
}
trap cleanup EXIT HUP INT TERM

require_tooling() {
  if [ ! -x "$WHOATHERE_BIN" ]; then
    echo "whoathere_binary_not_executable=$WHOATHERE_BIN" >&2
    exit 64
  fi
  if [ ! -x "$HELPER" ]; then
    echo "helper_not_executable=$HELPER" >&2
    exit 64
  fi
}

require_guest_tooling_receipt() {
  set +e
  doctor_output=$("$WHOATHERE_BIN" doctor --json --state-dir "$STATE_DIR" --helper "$HELPER" 2>&1)
  doctor_status=$?
  set -e
  printf '%s\n' "$doctor_output"
  if [ "$doctor_status" -ne 0 ]; then
    echo "doctor_failed_before_npm_uv_validation=true" >&2
    exit "$doctor_status"
  fi
  case "$doctor_output" in
    *'"guest_reprovision_required": true'*|*macos_vm_guest_node_runtime_not_provisioned*|*macos_vm_guest_uv_binary_not_provisioned*|*macos_vm_guest_python_runtime_not_provisioned*|*macos_vm_guest_pip_tooling_not_provisioned*)
      echo "guest_tooling_not_ready_for_npm_uv_validation=true" >&2
      "$SCRIPT_DIR/provision-guest-readiness.sh" --preflight "$STATE_DIR" >&2 || true
      echo "reprovision_command=$(whoathere_reprovision_command "$HELPER_ROOT" "$STATE_DIR")" >&2
      exit 64
      ;;
  esac
}

poll_guest_health() {
  attempt=1
  while [ "$attempt" -le "$HEALTH_ATTEMPTS" ]; do
    set +e
    HEALTH_OUTPUT=$("$HELPER" health --state-dir "$STATE_DIR" --json 2>&1)
    health_status=$?
    set -e
    printf 'health_attempt=%s exit=%s\n%s\n' "$attempt" "$health_status" "$HEALTH_OUTPUT"
    if [ "$health_status" -eq 0 ]; then
      return 0
    fi
    if [ "$health_status" -ne 20 ]; then
      return "$health_status"
    fi
    attempt=$((attempt + 1))
    sleep "$HEALTH_INTERVAL_SECONDS"
  done
  return 20
}

ensure_vm_running() {
  set +e
  HEALTH_OUTPUT=$("$HELPER" health --state-dir "$STATE_DIR" --json 2>&1)
  health_status=$?
  set -e
  if [ "$health_status" -eq 0 ]; then
    printf '%s\n' "$HEALTH_OUTPUT"
    return
  fi

  echo "vm_start_required_for_npm_uv_validation=true"
  "$WHOATHERE_BIN" vm start --state-dir "$STATE_DIR" --helper "$HELPER" --execute
  STARTED_BY_SCRIPT=1
  poll_guest_health
}

require_health_flag() {
  flag=$1
  case "$HEALTH_OUTPUT" in
    *"\"$flag\" : true"*|*"\"$flag\": true"*) ;;
    *)
      echo "guest_health_flag_missing_or_false=$flag" >&2
      printf '%s\n' "$HEALTH_OUTPUT" >&2
      exit 1
      ;;
  esac
}

require_guest_toolchains_live() {
  require_health_flag guest_toolchain_python3_available
  require_health_flag guest_toolchain_pip_available
  require_health_flag guest_toolchain_npm_available
  require_health_flag guest_toolchain_uv_available
}

write_npm_lockfile() {
  project=$1
  name=$2
  has_install_script=$3
  if [ "$has_install_script" = "true" ]; then
    install_script_line=',"hasInstallScript":true'
  else
    install_script_line=''
  fi
  cat > "$project/package-lock.json" <<EOF
{
  "name": "$name",
  "version": "0.0.1",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "$name",
      "version": "0.0.1"$install_script_line
    }
  }
}
EOF
}

write_clean_npm_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/package.json" <<'EOF'
{
  "name": "whoathere-clean-npm",
  "version": "0.0.1",
  "private": true,
  "main": "index.js",
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}
EOF
  cat > "$project/postinstall.js" <<'EOF'
require("fs").writeFileSync("clean.marker", "postinstall-ok");
EOF
  cat > "$project/index.js" <<'EOF'
exports.run = function() {
  require("fs").writeFileSync("clean.marker", "api-ok");
};
EOF
  write_npm_lockfile "$project" "whoathere-clean-npm" true
}

write_npm_lifecycle_canary_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/package.json" <<'EOF'
{
  "name": "whoathere-npm-lifecycle-canary",
  "version": "0.0.1",
  "private": true,
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}
EOF
  cat > "$project/postinstall.js" <<'EOF'
const fs = require("fs");
if (process.env.NPM_TOKEN || process.env.GITHUB_TOKEN) {
  fs.writeFileSync("canary-read.marker", "1");
}
EOF
  write_npm_lockfile "$project" "whoathere-npm-lifecycle-canary" true
}

write_npm_api_canary_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/package.json" <<'EOF'
{
  "name": "whoathere-npm-api-canary",
  "version": "0.0.1",
  "private": true,
  "main": "index.js"
}
EOF
  cat > "$project/index.js" <<'EOF'
exports.run = function() {
  if (process.env.NPM_TOKEN || process.env.GITHUB_TOKEN) {
    require("fs").writeFileSync("api-canary-read.marker", "1");
  }
};
EOF
  write_npm_lockfile "$project" "whoathere-npm-api-canary" false
}

write_npm_public_dependency_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/package.json" <<'EOF'
{
  "name": "whoathere-npm-public-dependency",
  "version": "0.0.1",
  "private": true,
  "dependencies": {
    "left-pad": "1.3.0"
  }
}
EOF
}

write_clean_uv_project() {
  project=$1
  module=${2:-whoathere_clean_uv}
  mkdir -p "$project"
  cat > "$project/setup.py" <<EOF
from setuptools import setup
setup(name="whoathere-clean-uv", version="0.0.1", py_modules=["$module"])
EOF
  cat > "$project/$module.py" <<'EOF'
VALUE = "clean"
EOF
}

write_uv_import_canary_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/setup.py" <<'EOF'
from setuptools import setup
setup(name="whoathere-uv-import-canary", version="0.0.1", py_modules=["whoathere_uv_import_canary"])
EOF
  cat > "$project/whoathere_uv_import_canary.py" <<'EOF'
import os
import pathlib
if os.environ.get("PYPI_TOKEN"):
    pathlib.Path("import-canary-read.marker").write_text("1")
VALUE = "import-canary"
EOF
}

write_uv_public_requirement_project() {
  project=$1
  write_clean_uv_project "$project"
  printf 'requests\n' > "$project/requirements.txt"
}

write_uv_sync_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/pyproject.toml" <<'EOF'
[project]
name = "whoathere-uv-sync-deferred"
version = "0.0.1"
EOF
}

assert_no_host_markers() {
  project=$1
  if find "$project" \( -name 'canary-read.marker' -o -name 'api-canary-read.marker' -o -name 'import-canary-read.marker' -o -name 'node_modules' -o -name 'target' \) -print | grep . >/dev/null; then
    echo "host_project_modified_or_marker_present=$project" >&2
    find "$project" \( -name 'canary-read.marker' -o -name 'api-canary-read.marker' -o -name 'import-canary-read.marker' -o -name 'node_modules' -o -name 'target' \) -print >&2
    exit 1
  fi
}

assert_output_sanitized() {
  output=$1
  case "$output" in
    *whoathere_fake_npm_token*|*whoathere_fake_pypi_token*|*whoathere_fake_github_token*|*WHOATHEREFAKEAWSKEY*|*whoathere_fake_aws_secret*|*whoathere_fake_openai_token*)
      echo "raw_canary_value_leaked=true" >&2
      exit 1
      ;;
  esac
}

run_project_case() {
  name=$1
  expected_status=$2
  expected_text=$3
  project=$4
  tool=$5
  shift 5

  echo "npm_uv_project_case=$name expected_exit=$expected_status tool=$tool"
  set +e
  output=$("$WHOATHERE_BIN" vm detonate \
    --workspace "$project" \
    --state-dir "$STATE_DIR" \
    --helper "$HELPER" \
    --timeout-seconds 180 \
    --execute \
    --json \
    "$tool" -- "$@" 2>&1)
  status=$?
  set -e
  printf '%s\n' "$output"
  assert_output_sanitized "$output"
  if [ "$status" -ne "$expected_status" ]; then
    echo "npm_uv_project_case_result=failed name=$name actual_exit=$status expected_exit=$expected_status" >&2
    exit 1
  fi
  case "$output" in
    *"$expected_text"*) ;;
    *)
      echo "npm_uv_project_case_result=failed name=$name expected_text_missing=$expected_text" >&2
      exit 1
      ;;
  esac
  assert_no_host_markers "$project"
  echo "npm_uv_project_case_result=ok name=$name actual_exit=$status"
}

run_preflight_case() {
  name=$1
  expected_text=$2
  project=$3
  tool=$4
  shift 4

  echo "npm_uv_preflight_case=$name expected_exit=20 tool=$tool"
  set +e
  output=$("$WHOATHERE_BIN" vm detonate \
    --workspace "$project" \
    --state-dir "$STATE_DIR" \
    --helper "$HELPER" \
    --timeout-seconds 180 \
    --execute \
    --json \
    "$tool" -- "$@" 2>&1)
  status=$?
  set -e
  printf '%s\n' "$output"
  assert_output_sanitized "$output"
  if [ "$status" -ne 20 ]; then
    echo "npm_uv_preflight_case_result=failed name=$name actual_exit=$status expected_exit=20" >&2
    exit 1
  fi
  case "$output" in
    *"$expected_text"*) ;;
    *)
      echo "npm_uv_preflight_case_result=failed name=$name expected_text_missing=$expected_text" >&2
      exit 1
      ;;
  esac
  case "$output" in
    *'"helper": null'*) ;;
    *)
      echo "npm_uv_preflight_case_result=failed name=$name helper_was_invoked_or_not_proven=false" >&2
      exit 1
      ;;
  esac
  assert_no_host_markers "$project"
  echo "npm_uv_preflight_case_result=ok name=$name actual_exit=$status"
}

write_release_validation_receipt() {
  provisioning_receipt="$STATE_DIR/bundle/guest-provisioning.json"
  if [ ! -f "$provisioning_receipt" ]; then
    echo "guest_provisioning_receipt_missing_before_release_validation_write=true" >&2
    exit 1
  fi
  provisioning_digest=sha256:$(shasum -a 256 "$provisioning_receipt" | awk '{print $1}')
  created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  mkdir -p "$(dirname -- "$RELEASE_VALIDATION_RECEIPT")"
  temp_receipt="$RELEASE_VALIDATION_RECEIPT.$$"
  cat > "$temp_receipt" <<EOF
{
  "schema_version": "whoathere.macos_vm.release_validation.v1",
  "validator": "validate-npm-uv-detonation.sh",
  "created_at_utc": "$created_at",
  "guest_provisioning_receipt_digest": "$provisioning_digest",
  "npm_vm_detonation_verified": true,
  "uv_vm_detonation_verified": true,
  "live_guest_toolchains_verified": true,
  "host_package_execution_enabled": false,
  "sync_back_enabled": false,
  "high_risk_package_execution_enabled": false,
  "package_acquisition_policy": "local_only_no_public_resolver"
}
EOF
  mv "$temp_receipt" "$RELEASE_VALIDATION_RECEIPT"
  echo "release_validation_receipt=$RELEASE_VALIDATION_RECEIPT"
  echo "release_validation_guest_provisioning_receipt_digest=$provisioning_digest"
}

require_tooling
mkdir -p "$WORK_ROOT"
require_guest_tooling_receipt
ensure_vm_running
require_guest_toolchains_live

clean_npm="$WORK_ROOT/clean-npm"
write_clean_npm_project "$clean_npm"
run_project_case npm_install_clean 0 allow_observed_clean "$clean_npm" npm install
run_project_case npm_ci_clean 0 allow_observed_clean "$clean_npm" npm ci

npm_lifecycle="$WORK_ROOT/npm-lifecycle-canary"
write_npm_lifecycle_canary_project "$npm_lifecycle"
run_project_case npm_lifecycle_canary 20 deny_malicious_behavior "$npm_lifecycle" npm install

npm_api="$WORK_ROOT/npm-api-canary"
write_npm_api_canary_project "$npm_api"
run_project_case npm_api_canary 20 deny_malicious_behavior "$npm_api" npm install

npm_public="$WORK_ROOT/npm-public"
write_npm_public_dependency_project "$npm_public"
run_preflight_case npm_public_dependency project_npm_dependency_resolution_deferred "$npm_public" npm install

clean_uv="$WORK_ROOT/clean-uv"
write_clean_uv_project "$clean_uv"
run_project_case uv_pip_clean 0 allow_observed_clean "$clean_uv" uv pip install .

uv_import="$WORK_ROOT/uv-import-canary"
write_uv_import_canary_project "$uv_import"
run_project_case uv_import_canary 20 deny_malicious_behavior "$uv_import" uv pip install .

uv_public="$WORK_ROOT/uv-public"
write_uv_public_requirement_project "$uv_public"
run_preflight_case uv_public_requirement project_requirements_public_resolution_deferred "$uv_public" uv pip install -r requirements.txt

uv_sync="$WORK_ROOT/uv-sync"
write_uv_sync_project "$uv_sync"
run_preflight_case uv_sync_deferred project_uv_sync_deferred_until_lock_policy "$uv_sync" uv sync

write_release_validation_receipt
echo "npm_uv_detonation_validation=ok"
