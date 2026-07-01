#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ARCHIVE=""
STATE_DIR=${WHOATHERE_RUNTIME_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}
RECEIPT_PATH=""
HANDOFF_PATH=${WHOATHERE_RUNTIME_REPROVISION_HANDOFF:-}
KEEP_WORK=false
ATTEMPT_SUDO=false
WORK_ROOT=""
PRESERVE_WORK=false
STARTED_VM=false
SCANNER_CACHE_DIR=${WHOATHERE_SCANNER_CACHE_DIR:-${WHOATHERE_SCANNER_CACHE:-"$HOME/.whoathere/scanners"}}

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-runtime-qualification.sh --archive <preview.tar.gz> [--state-dir <dir>] [--receipt <path>] [--attempt-sudo] [--keep-work]

Runs Goal 2 Track 2 same-host runtime qualification from the notarized installed package.
This uses a clean temporary HOME, minimal PATH, temporary install prefix, fresh test workspaces,
and the installed wrapper only. It validates the physical-host Apple Virtualization.framework
runtime path and does not require nested macOS virtualization.
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --archive)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      ARCHIVE=$2
      shift 2
      ;;
    --archive=*)
      ARCHIVE=${1#--archive=}
      shift
      ;;
    --state-dir)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      STATE_DIR=$2
      shift 2
      ;;
    --state-dir=*)
      STATE_DIR=${1#--state-dir=}
      shift
      ;;
    --receipt)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      RECEIPT_PATH=$2
      shift 2
      ;;
    --receipt=*)
      RECEIPT_PATH=${1#--receipt=}
      shift
      ;;
    --attempt-sudo)
      ATTEMPT_SUDO=true
      shift
      ;;
    --keep-work)
      KEEP_WORK=true
      shift
      ;;
    --help|-h)
      usage
      ;;
    *)
      if [ -z "$ARCHIVE" ]; then
        ARCHIVE=$1
        shift
      else
        usage
      fi
      ;;
  esac
done

cleanup() {
  if [ "$STARTED_VM" = "true" ] && [ -x "${WRAPPER:-}" ]; then
    run_clean "$WRAPPER" vm suspend --state-dir "$STATE_DIR" --execute >/dev/null 2>&1 || true
  fi
  if [ "$KEEP_WORK" != "true" ] && [ "$PRESERVE_WORK" != "true" ] && [ -n "$WORK_ROOT" ]; then
    rm -rf "$WORK_ROOT"
  elif [ -n "$WORK_ROOT" ]; then
    echo "runtime_qualification_work_root=$WORK_ROOT"
  fi
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "runtime_qualification_failed=$1" >&2
  exit 1
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

require_contains() {
  PATTERN=$1
  FILE=$2
  REASON=$3
  if ! grep -q "$PATTERN" "$FILE"; then
    if [ -f "$FILE" ]; then
      echo "runtime_qualification_output_file=$FILE" >&2
      cat "$FILE" >&2
    fi
    fail "$REASON"
  fi
}

require_health_contains() {
  JSON_FIELD=$1
  LEGACY_FIELD=$2
  FILE=$3
  REASON=$4
  if grep -q "$LEGACY_FIELD=true" "$FILE"; then
    return
  fi
  if grep -q "\"$JSON_FIELD\" : true" "$FILE"; then
    return
  fi
  echo "runtime_qualification_output_file=$FILE" >&2
  cat "$FILE" >&2
  fail "$REASON"
}

require_host() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "macos_host_required=true" >&2
    exit 64
  fi
  if [ "$(uname -m)" != "arm64" ]; then
    echo "apple_silicon_arm64_required=true" >&2
    exit 64
  fi
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print "sha256:" $1}'
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_string_field() {
  field=$1
  file=$2
  sed -n "s/.*\"$field\": \"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

run_clean() {
  env -i \
    HOME="$CLEAN_HOME" \
    TMPDIR="$CLEAN_TMP/" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    WHOATHERE_SCANNER_CACHE_DIR="$SCANNER_CACHE_DIR" \
    "$@"
}

run_clean_with_sources() {
  env -i \
    HOME="$CLEAN_HOME" \
    TMPDIR="$CLEAN_TMP/" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    WHOATHERE_SCANNER_CACHE_DIR="$SCANNER_CACHE_DIR" \
    WHOATHERE_PYTHON_RUNTIME_DIR="$PYTHON_RUNTIME_DIR" \
    WHOATHERE_PYTHON_WHEEL_DIR="$PYTHON_WHEEL_DIR" \
    WHOATHERE_WHEEL_PACKAGE_FILE="$WHEEL_PACKAGE_FILE" \
    WHOATHERE_NODE_RUNTIME_DIR="$NODE_RUNTIME_DIR" \
    WHOATHERE_UV_BINARY="$UV_BINARY" \
    "$@"
}

require_archive() {
  if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
    echo "archive_not_found=$ARCHIVE" >&2
    usage
  fi
  case "$ARCHIVE" in
    *.tar.gz) ;;
    *)
      echo "archive_must_be_tar_gz=$ARCHIVE" >&2
      exit 64
      ;;
  esac
  ARCHIVE=$(CDPATH= cd -- "$(dirname -- "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")
  PACKAGE_NAME=$(basename "$ARCHIVE" .tar.gz)
  if [ -z "$RECEIPT_PATH" ]; then
    RECEIPT_PATH="$REPO_ROOT/dist/$PACKAGE_NAME-runtime-qualification.json"
  fi
  if [ -z "$HANDOFF_PATH" ]; then
    HANDOFF_PATH="$REPO_ROOT/dist/$PACKAGE_NAME-runtime-reprovision.sh"
  fi
}

verify_checksum() {
  if [ ! -f "$ARCHIVE.sha256" ]; then
    fail archive_checksum_sidecar_missing
  fi
  (
    cd "$(dirname "$ARCHIVE")"
    shasum -a 256 -c "$(basename "$ARCHIVE").sha256"
  )
}

first_existing_python_runtime() {
  if [ -n "${WHOATHERE_PYTHON_RUNTIME_DIR:-}" ] && [ -x "$WHOATHERE_PYTHON_RUNTIME_DIR/bin/python3" ]; then
    printf '%s\n' "$WHOATHERE_PYTHON_RUNTIME_DIR"
    return
  fi
  for candidate in \
    "$HOME/.local/share/uv/python/cpython-3.11.11-macos-aarch64-none" \
    "$HOME/.local/share/uv/python/cpython-3.12.11-macos-aarch64-none" \
    "$HOME/.local/share/uv/python/cpython-3.13.2-macos-aarch64-none" \
    "$HOME/.local/share/uv/python/cpython-3.10.20-macos-aarch64-none"; do
    if [ -x "$candidate/bin/python3" ]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
}

first_python_wheel_dir() {
  if [ -n "${WHOATHERE_PYTHON_WHEEL_DIR:-}" ] \
    && [ -n "$(find "$WHOATHERE_PYTHON_WHEEL_DIR" -maxdepth 1 -name 'pip-*.whl' -type f -print -quit 2>/dev/null)" ] \
    && [ -n "$(find "$WHOATHERE_PYTHON_WHEEL_DIR" -maxdepth 1 -name 'setuptools-*.whl' -type f -print -quit 2>/dev/null)" ]; then
    printf '%s\n' "$WHOATHERE_PYTHON_WHEEL_DIR"
    return
  fi
  if [ -n "${PYTHON_RUNTIME_DIR:-}" ] && [ -d "$PYTHON_RUNTIME_DIR/lib" ]; then
    found=$(find "$PYTHON_RUNTIME_DIR" -path '*/ensurepip/_bundled' -type d -print -quit 2>/dev/null || true)
    if [ -n "$found" ]; then
      printf '%s\n' "$found"
      return
    fi
  fi
}

first_wheel_package() {
  if [ -n "${WHOATHERE_WHEEL_PACKAGE_FILE:-}" ] && [ -f "$WHOATHERE_WHEEL_PACKAGE_FILE" ]; then
    printf '%s\n' "$WHOATHERE_WHEEL_PACKAGE_FILE"
    return
  fi
  find "$HOME/Library/Caches/pypoetry/artifacts" "$HOME/.cache/codex-runtimes" \
    -name 'wheel-*.whl' -type f -print -quit 2>/dev/null || true
}

first_node_runtime() {
  if [ -n "${WHOATHERE_NODE_RUNTIME_DIR:-}" ] \
    && [ -x "$WHOATHERE_NODE_RUNTIME_DIR/bin/node" ] \
    && [ -x "$WHOATHERE_NODE_RUNTIME_DIR/bin/npm" ]; then
    printf '%s\n' "$WHOATHERE_NODE_RUNTIME_DIR"
    return
  fi
  if [ -d "$HOME/.nvm/versions/node" ]; then
    found=$(find "$HOME/.nvm/versions/node" -maxdepth 1 -type d -name 'v*' -print 2>/dev/null | sort | tail -n 1)
    if [ -n "$found" ] && [ -x "$found/bin/node" ] && [ -x "$found/bin/npm" ]; then
      printf '%s\n' "$found"
      return
    fi
  fi
  if command -v node >/dev/null 2>&1; then
    node_dir=$(CDPATH= cd -- "$(dirname -- "$(command -v node)")/.." && pwd)
    if [ -x "$node_dir/bin/node" ] && [ -x "$node_dir/bin/npm" ]; then
      printf '%s\n' "$node_dir"
      return
    fi
  fi
}

first_uv_binary() {
  if [ -n "${WHOATHERE_UV_BINARY:-}" ] && [ -x "$WHOATHERE_UV_BINARY" ]; then
    printf '%s\n' "$WHOATHERE_UV_BINARY"
    return
  fi
  if [ -x "$HOME/.local/bin/uv" ]; then
    printf '%s\n' "$HOME/.local/bin/uv"
    return
  fi
  command -v uv 2>/dev/null || true
}

detect_tool_sources() {
  PYTHON_RUNTIME_DIR=$(first_existing_python_runtime || true)
  PYTHON_WHEEL_DIR=$(first_python_wheel_dir || true)
  WHEEL_PACKAGE_FILE=$(first_wheel_package || true)
  NODE_RUNTIME_DIR=$(first_node_runtime || true)
  UV_BINARY=$(first_uv_binary || true)
}

install_package() {
  tar -xzf "$ARCHIVE" -C "$WORK_ROOT/extract"
  EXTRACTED_ROOT="$WORK_ROOT/extract/$PACKAGE_NAME"
  INSTALL_PREFIX="$WORK_ROOT/install prefix's"
  "$EXTRACTED_ROOT/install-macos-preview.sh" --prefix "$INSTALL_PREFIX" >/dev/null
  WRAPPER="$INSTALL_PREFIX/bin/whoathere"
  INSTALLED_RELEASE_DIR="$INSTALL_PREFIX/releases/$PACKAGE_NAME"
  INSTALLED_HELPER="$INSTALLED_RELEASE_DIR/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  HELPER_ROOT="$INSTALLED_RELEASE_DIR/helpers/macos-vm-helper"
  PROVISIONER="$HELPER_ROOT/scripts/provision-guest-readiness.sh"
  PROJECT_VALIDATOR="$HELPER_ROOT/scripts/validate-project-detonation.sh"
  NPM_UV_VALIDATOR="$HELPER_ROOT/scripts/validate-npm-uv-detonation.sh"
  FIXTURE_VALIDATOR="$HELPER_ROOT/scripts/validate-detonation-fixtures.sh"

  test -x "$WRAPPER" || fail installed_wrapper_missing
  test -x "$INSTALLED_HELPER" || fail installed_helper_missing
  test -x "$PROVISIONER" || fail installed_provisioner_missing
  test -x "$PROJECT_VALIDATOR" || fail installed_project_validator_missing
  test -x "$NPM_UV_VALIDATOR" || fail installed_npm_uv_validator_missing
  test -x "$FIXTURE_VALIDATOR" || fail installed_fixture_validator_missing
}

sudo_command() {
  printf 'sudo'
  printf ' WHOATHERE_PYTHON_RUNTIME_DIR=%s' "$(shell_quote "$PYTHON_RUNTIME_DIR")"
  printf ' WHOATHERE_PYTHON_WHEEL_DIR=%s' "$(shell_quote "$PYTHON_WHEEL_DIR")"
  printf ' WHOATHERE_WHEEL_PACKAGE_FILE=%s' "$(shell_quote "$WHEEL_PACKAGE_FILE")"
  printf ' WHOATHERE_NODE_RUNTIME_DIR=%s' "$(shell_quote "$NODE_RUNTIME_DIR")"
  printf ' WHOATHERE_UV_BINARY=%s' "$(shell_quote "$UV_BINARY")"
  printf ' %s %s\n' "$(shell_quote "$PROVISIONER")" "$(shell_quote "$STATE_DIR")"
}

write_reprovision_handoff() {
  command_text=$1
  handoff_dir=$(dirname "$HANDOFF_PATH")
  mkdir -p "$handoff_dir"
  temp_handoff="$HANDOFF_PATH.$$"
  {
    printf '%s\n' '#!/bin/sh'
    printf '%s\n' 'set -eu'
    printf 'cd %s\n' "$(shell_quote "$REPO_ROOT")"
    printf '%s\n' ''
    printf '%s\n' '# Original preflight command for operator inspection:'
    printf '# %s\n' "$command_text"
    printf 'archive=%s\n' "$(shell_quote "$ARCHIVE")"
    printf 'package_name=%s\n' "$(shell_quote "$PACKAGE_NAME")"
    printf 'state_dir=%s\n' "$(shell_quote "$STATE_DIR")"
    printf 'handoff_tmp=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-runtime-reprovision.XXXXXX")\n'
    printf '%s\n' 'cleanup() { rm -rf "$handoff_tmp"; }'
    printf '%s\n' 'trap cleanup EXIT HUP INT TERM'
    printf '%s\n' 'tar -xzf "$archive" -C "$handoff_tmp"'
    printf '%s\n' 'provisioner="$handoff_tmp/$package_name/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh"'
    printf '%s\n' 'test -x "$provisioner"'
    printf 'sudo WHOATHERE_PYTHON_RUNTIME_DIR=%s \\\n' "$(shell_quote "$PYTHON_RUNTIME_DIR")"
    printf '  WHOATHERE_PYTHON_WHEEL_DIR=%s \\\n' "$(shell_quote "$PYTHON_WHEEL_DIR")"
    printf '  WHOATHERE_WHEEL_PACKAGE_FILE=%s \\\n' "$(shell_quote "$WHEEL_PACKAGE_FILE")"
    printf '  WHOATHERE_NODE_RUNTIME_DIR=%s \\\n' "$(shell_quote "$NODE_RUNTIME_DIR")"
    printf '  WHOATHERE_UV_BINARY=%s \\\n' "$(shell_quote "$UV_BINARY")"
    printf '%s\n' '  "$provisioner" "$state_dir"'
    printf '%s\n' 'echo "runtime_reprovision_handoff_sudo=ok"'
    printf 'exec %s --archive %s --state-dir %s --attempt-sudo\n' \
      "$(shell_quote "$REPO_ROOT/scripts/whoathere-runtime-qualification.sh")" \
      "$(shell_quote "$ARCHIVE")" \
      "$(shell_quote "$STATE_DIR")"
  } > "$temp_handoff"
  chmod 0700 "$temp_handoff"
  mv "$temp_handoff" "$HANDOFF_PATH"
}

attempt_sudo_provision() {
  sudo -n env \
    WHOATHERE_PYTHON_RUNTIME_DIR="$PYTHON_RUNTIME_DIR" \
    WHOATHERE_PYTHON_WHEEL_DIR="$PYTHON_WHEEL_DIR" \
    WHOATHERE_WHEEL_PACKAGE_FILE="$WHEEL_PACKAGE_FILE" \
    WHOATHERE_NODE_RUNTIME_DIR="$NODE_RUNTIME_DIR" \
    WHOATHERE_UV_BINARY="$UV_BINARY" \
    "$PROVISIONER" "$STATE_DIR"
}

check_reprovisioning() {
  DOCTOR_BEFORE="$WORK_ROOT/doctor-before.json"
  run_clean "$WRAPPER" doctor --json --state-dir "$STATE_DIR" > "$DOCTOR_BEFORE"
  if ! grep -q '"guest_reprovision_required": true' "$DOCTOR_BEFORE"; then
    return
  fi

  PREFLIGHT_OUTPUT="$WORK_ROOT/reprovision-preflight.txt"
  set +e
  run_clean_with_sources "$WRAPPER" vm reprovision --preflight --state-dir "$STATE_DIR" > "$PREFLIGHT_OUTPUT" 2>&1
  preflight_status=$?
  set -e
  cat "$PREFLIGHT_OUTPUT"

  require_contains 'ready_for_sudo_provisioning=true' "$PREFLIGHT_OUTPUT" reprovision_preflight_not_ready

  command_text=$(sudo_command)
  write_reprovision_handoff "$command_text"
  echo "runtime_reprovision_required=true" >&2
  echo "runtime_reprovision_command=$command_text" >&2
  echo "runtime_reprovision_handoff=$HANDOFF_PATH" >&2

  if [ "$ATTEMPT_SUDO" != "true" ]; then
    PRESERVE_WORK=true
    exit 64
  fi

  set +e
  attempt_sudo_provision
  sudo_status=$?
  set -e
  if [ "$sudo_status" -ne 0 ]; then
    echo "runtime_reprovision_sudo_status=$sudo_status" >&2
    echo "runtime_reprovision_command=$command_text" >&2
    PRESERVE_WORK=true
    exit "$sudo_status"
  fi

  run_clean "$WRAPPER" doctor --json --state-dir "$STATE_DIR" > "$WORK_ROOT/doctor-after-reprovision.json"
  if grep -q '"guest_reprovision_required": true' "$WORK_ROOT/doctor-after-reprovision.json"; then
    cat "$WORK_ROOT/doctor-after-reprovision.json" >&2
    fail reprovision_did_not_clear_guest_reprovision_required
  fi
}

start_and_health() {
  run_clean "$WRAPPER" vm start --state-dir "$STATE_DIR" --execute > "$WORK_ROOT/vm-start.txt"
  STARTED_VM=true
  attempt=1
  while [ "$attempt" -le 30 ]; do
    set +e
    run_clean "$WRAPPER" vm health --state-dir "$STATE_DIR" > "$WORK_ROOT/vm-health.txt" 2>&1
    status=$?
    set -e
    if [ "$status" -eq 0 ]; then
      cat "$WORK_ROOT/vm-health.txt"
      require_health_contains 'guest_health_proven' 'guest_health_proven' "$WORK_ROOT/vm-health.txt" health_guest_not_proven
      require_health_contains 'guest_toolchain_python3_available' 'guest_toolchain_python3_available' "$WORK_ROOT/vm-health.txt" health_python_missing
      require_health_contains 'guest_toolchain_pip_available' 'guest_toolchain_pip_available' "$WORK_ROOT/vm-health.txt" health_pip_missing
      require_health_contains 'guest_toolchain_npm_available' 'guest_toolchain_npm_available' "$WORK_ROOT/vm-health.txt" health_npm_missing
      require_health_contains 'guest_toolchain_uv_available' 'guest_toolchain_uv_available' "$WORK_ROOT/vm-health.txt" health_uv_missing
      return
    fi
    sleep 10
    attempt=$((attempt + 1))
  done
  cat "$WORK_ROOT/vm-health.txt" >&2
  fail vm_health_not_ready
}

run_packaged_validators() {
  set +e
  WHOATHERE_BIN="$WRAPPER" WHOATHERE_MACOS_VM_HELPER="$INSTALLED_HELPER" WHOATHERE_VM_STATE_DIR="$STATE_DIR" \
    HOME="$CLEAN_HOME" TMPDIR="$CLEAN_TMP/" PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    "$PROJECT_VALIDATOR" > "$WORK_ROOT/project-validation.txt" 2>&1
  project_status=$?
  set -e
  if [ "$project_status" -ne 0 ]; then
    cat "$WORK_ROOT/project-validation.txt" >&2
    fail project_validator_command_failed
  fi
  require_contains 'project_detonation_validation=ok' "$WORK_ROOT/project-validation.txt" project_validation_failed

  set +e
  WHOATHERE_VM_HEALTH_INTERVAL_SECONDS=1 WHOATHERE_VM_HEALTH_ATTEMPTS=3 \
    WHOATHERE_BIN="$WRAPPER" WHOATHERE_MACOS_VM_HELPER="$INSTALLED_HELPER" WHOATHERE_VM_STATE_DIR="$STATE_DIR" \
    HOME="$CLEAN_HOME" TMPDIR="$CLEAN_TMP/" PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    "$NPM_UV_VALIDATOR" > "$WORK_ROOT/npm-uv-validation.txt" 2>&1
  npm_uv_status=$?
  set -e
  if [ "$npm_uv_status" -ne 0 ]; then
    cat "$WORK_ROOT/npm-uv-validation.txt" >&2
    fail npm_uv_validator_command_failed
  fi
  require_contains 'npm_uv_detonation_validation=ok' "$WORK_ROOT/npm-uv-validation.txt" npm_uv_validation_failed

  set +e
  WHOATHERE_BIN="$WRAPPER" WHOATHERE_MACOS_VM_HELPER="$INSTALLED_HELPER" WHOATHERE_VM_STATE_DIR="$STATE_DIR" \
    HOME="$CLEAN_HOME" TMPDIR="$CLEAN_TMP/" PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    "$FIXTURE_VALIDATOR" > "$WORK_ROOT/fixture-validation.txt" 2>&1
  fixture_status=$?
  set -e
  if [ "$fixture_status" -ne 0 ]; then
    cat "$WORK_ROOT/fixture-validation.txt" >&2
    fail fixture_validator_command_failed
  fi
  require_contains 'detonation_fixture_validation=ok' "$WORK_ROOT/fixture-validation.txt" fixture_validation_failed
}

write_sync_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/package.json" <<'EOF'
{
  "name": "whoathere-sync-clean-npm",
  "version": "0.0.1",
  "whoatherePublishedAtUnixSeconds": 1700000000,
  "repository": "whoathere-sync-clean-npm"
}
EOF
}

write_sync_canary_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/pyproject.toml" <<'EOF'
[project]
name = "whoathere-sync-canary"
version = "0.0.1"
whoathere-published-at = 1700000000

[project.urls]
Repository = "https://example.invalid/whoathere-sync-canary"
EOF
  cat > "$project/setup.py" <<'EOF'
from setuptools import setup
import os
import pathlib
if os.environ.get("PYPI_TOKEN"):
    pathlib.Path("sync-canary-read.marker").write_text("1")
setup(name="whoathere-sync-canary", version="0.0.1", py_modules=["whoathere_sync_canary"])
EOF
  cat > "$project/whoathere_sync_canary.py" <<'EOF'
VALUE = "sync-canary"
EOF
}

write_scanner_receipt_for_workspace() {
  workspace=$1
  receipt=$2
  ecosystem=$3
  receipt_dir=$(dirname "$receipt")
  mkdir -p "$receipt_dir"
  set +e
  run_clean "$WRAPPER" scanners run \
    --workspace "$workspace" \
    --ecosystem "$ecosystem" \
    --state-dir "$STATE_DIR" \
    --execute \
    --json > "$receipt"
  scanner_status=$?
  set -e
  case "$scanner_status" in
    0|20|22) ;;
    *)
      cat "$receipt" >&2
      fail scanner_run_failed
      ;;
  esac
  require_contains '"scanner_receipt_auth"' "$receipt" scanner_receipt_auth_missing
}

latest_package_risk_receipt() {
  find "$STATE_DIR/package-risk/receipts" -name '*.json' -type f 2>/dev/null | sort | tail -n 1
}

prepare_package_risk_receipt_for_workspace() {
  workspace=$1
  scanner_receipt=$2
  assessment_output=$3
  ecosystem=$4
  before_receipt=$(latest_package_risk_receipt || true)
  write_scanner_receipt_for_workspace "$workspace" "$scanner_receipt" "$ecosystem"
  set +e
  run_clean "$WRAPPER" package-risk assess \
    --workspace "$workspace" \
    --ecosystem "$ecosystem" \
    --state-dir "$STATE_DIR" \
    --scanner-receipt "$scanner_receipt" \
    --json > "$assessment_output" 2>&1
  assess_status=$?
  set -e
  case "$assess_status" in
    0|20|22) ;;
    *)
      cat "$assessment_output" >&2
      fail package_risk_assess_failed
      ;;
  esac
  after_receipt=$(latest_package_risk_receipt || true)
  if [ -z "$after_receipt" ] || [ "$after_receipt" = "$before_receipt" ]; then
    cat "$assessment_output" >&2
    fail package_risk_receipt_missing
  fi
  printf '%s\n' "$after_receipt"
}

run_sync_back_cases() {
  clean_project="$WORK_ROOT/sync-clean"
  write_sync_project "$clean_project"
  clean_package_risk_receipt=$(prepare_package_risk_receipt_for_workspace \
    "$clean_project" \
    "$WORK_ROOT/package-risk/sync-clean-scanner.json" \
    "$WORK_ROOT/package-risk/sync-clean-assess.json" \
    "npm")
  require_contains '"overall_verdict": "auto_sync_candidate"' "$WORK_ROOT/package-risk/sync-clean-assess.json" sync_clean_package_risk_not_auto
  set +e
  run_clean "$WRAPPER" vm detonate \
    --workspace "$clean_project" \
    --state-dir "$STATE_DIR" \
    --package-risk-receipt "$clean_package_risk_receipt" \
    --timeout-seconds 180 \
    --execute \
    --sync-back \
    --json \
    npm -- install > "$WORK_ROOT/sync-clean.json" 2>&1
  clean_sync_status=$?
  set -e
  if [ "$clean_sync_status" -ne 0 ]; then
    cat "$WORK_ROOT/sync-clean.json" >&2
    fail sync_clean_command_failed
  fi
  require_contains '"verdict": "allow_observed_clean"' "$WORK_ROOT/sync-clean.json" sync_clean_verdict_missing
  require_contains '"applied": true' "$WORK_ROOT/sync-clean.json" sync_clean_not_applied
  test -f "$STATE_DIR/bundle/sync-validation.json" || fail sync_validation_receipt_missing_after_clean_sync

  canary_project="$WORK_ROOT/sync-canary"
  write_sync_canary_project "$canary_project"
  canary_package_risk_receipt=$(prepare_package_risk_receipt_for_workspace \
    "$canary_project" \
    "$WORK_ROOT/package-risk/sync-canary-scanner.json" \
    "$WORK_ROOT/package-risk/sync-canary-assess.json" \
    "pypi")
  set +e
  run_clean "$WRAPPER" vm detonate \
    --workspace "$canary_project" \
    --state-dir "$STATE_DIR" \
    --package-risk-receipt "$canary_package_risk_receipt" \
    --timeout-seconds 180 \
    --execute \
    --sync-back \
    --json \
    pip -- install . > "$WORK_ROOT/sync-canary.json" 2>&1
  canary_status=$?
  set -e
  test "$canary_status" -eq 20 || fail sync_canary_expected_deny
  require_contains '"applied": false' "$WORK_ROOT/sync-canary.json" sync_canary_applied_unexpectedly
  if find "$canary_project" -name 'sync-canary-read.marker' -print | grep . >/dev/null; then
    fail sync_canary_marker_written_on_host
  fi
}

suspend_and_verify() {
  run_clean "$WRAPPER" vm suspend --state-dir "$STATE_DIR" --execute > "$WORK_ROOT/vm-suspend.txt" 2>&1
  STARTED_VM=false
  test -f "$STATE_DIR/bundle/shutdown.json" || fail shutdown_receipt_missing_after_suspend
  run_clean "$WRAPPER" vm status --json --state-dir "$STATE_DIR" > "$WORK_ROOT/vm-status-after-suspend.json"
  require_contains '"runtime_ready": false' "$WORK_ROOT/vm-status-after-suspend.json" suspend_runtime_still_ready
  require_contains '"receipt_present": true' "$WORK_ROOT/vm-status-after-suspend.json" suspend_shutdown_receipt_not_reported
  require_contains '"receipt_acceptable_for_no_sync_preview": true' "$WORK_ROOT/vm-status-after-suspend.json" suspend_shutdown_receipt_not_acceptable
  require_contains '"high_risk_package_execution_enabled": false' "$WORK_ROOT/vm-status-after-suspend.json" suspend_high_risk_enabled_unexpectedly
}

final_doctor() {
  run_clean "$WRAPPER" doctor --json --state-dir "$STATE_DIR" > "$WORK_ROOT/doctor-final.json"
  require_contains '"release_ready": true' "$WORK_ROOT/doctor-final.json" final_doctor_release_not_ready
  require_contains '"guest_reprovision_required": false' "$WORK_ROOT/doctor-final.json" final_doctor_reprovision_required
  require_contains '"release_notarization": {' "$WORK_ROOT/doctor-final.json" final_doctor_notarization_missing
  require_contains '"verified": true' "$WORK_ROOT/doctor-final.json" final_doctor_verified_field_missing
  require_contains '"sync_validation": {' "$WORK_ROOT/doctor-final.json" final_doctor_sync_validation_missing
  require_contains '"release_blocking_reason_codes": \[\]' "$WORK_ROOT/doctor-final.json" final_doctor_blockers_present
}

write_receipt() {
  RECEIPT_DIR=$(dirname "$RECEIPT_PATH")
  mkdir -p "$RECEIPT_DIR"
  temp_receipt="$RECEIPT_PATH.$$"
  created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  archive_digest=$(sha256_file "$ARCHIVE")
  cli_digest=$(sha256_file "$INSTALLED_RELEASE_DIR/bin/whoathere")
  helper_digest=$(sha256_file "$INSTALLED_HELPER")
  sync_digest=$(sha256_file "$STATE_DIR/bundle/sync-validation.json")
  release_digest=$(sha256_file "$STATE_DIR/bundle/release-validation.json")
  provisioning_digest=$(sha256_file "$STATE_DIR/bundle/guest-provisioning.json")
  shutdown_digest=$(sha256_file "$STATE_DIR/bundle/shutdown.json")
  cat > "$temp_receipt" <<EOF
{
  "schema_version": "whoathere.macos_runtime_qualification.v1",
  "qualified": true,
  "created_at": "$(json_escape "$created_at")",
  "artifact_name": "$(json_escape "$PACKAGE_NAME")",
  "archive_path": "$(json_escape "$ARCHIVE")",
  "archive_sha256": "$(json_escape "$archive_digest")",
  "state_dir": "$(json_escape "$STATE_DIR")",
  "clean_home_used": true,
  "minimal_path_used": true,
  "physical_host_runtime": true,
  "nested_vm_runtime": false,
  "cli_sha256": "$(json_escape "$cli_digest")",
  "helper_sha256": "$(json_escape "$helper_digest")",
  "guest_provisioning_receipt_sha256": "$(json_escape "$provisioning_digest")",
  "release_validation_receipt_sha256": "$(json_escape "$release_digest")",
  "sync_validation_receipt_sha256": "$(json_escape "$sync_digest")",
  "shutdown_receipt_sha256": "$(json_escape "$shutdown_digest")",
  "vm_health_verified": true,
  "vm_suspend_verified": true,
  "project_validation_verified": true,
  "npm_uv_validation_verified": true,
  "fixture_validation_verified": true,
  "sync_back_clean_verified": true,
  "sync_back_malicious_no_sync_verified": true,
  "doctor_release_ready": true
}
EOF
  mv "$temp_receipt" "$RECEIPT_PATH"
}

require_host
require_archive
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-runtime-qualification.XXXXXX")
mkdir -p "$WORK_ROOT/extract"
CLEAN_HOME="$WORK_ROOT/clean home"
CLEAN_TMP="$WORK_ROOT/tmp"
mkdir -p "$CLEAN_HOME" "$CLEAN_TMP"

verify_checksum
detect_tool_sources
install_package
check_reprovisioning
start_and_health
run_packaged_validators
run_sync_back_cases
suspend_and_verify
final_doctor
write_receipt

echo "runtime_qualification_passed=true"
echo "runtime_qualification_receipt=$RECEIPT_PATH"
echo "runtime_qualification_state_dir=$STATE_DIR"
