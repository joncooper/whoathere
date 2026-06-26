#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$HELPER_ROOT/../../.." && pwd)

WHOATHERE_BIN=${WHOATHERE_BIN:-"$REPO_ROOT/target/debug/whoathere"}
HELPER=${WHOATHERE_MACOS_VM_HELPER:-"$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper"}
STATE_DIR=${WHOATHERE_VM_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}

run_case() {
  name=$1
  expected=$2
  tool=$3
  shift 3

  echo "fixture=$name expected_exit=$expected tool=$tool"
  set +e
  "$WHOATHERE_BIN" vm detonate \
    --state-dir "$STATE_DIR" \
    --helper "$HELPER" \
    --fixture "$name" \
    --timeout-seconds 120 \
    --execute \
    "$tool" -- "$@"
  status=$?
  set -e
  if [ "$status" -ne "$expected" ]; then
    echo "fixture_result=failed fixture=$name actual_exit=$status expected_exit=$expected" >&2
    exit 1
  fi
  echo "fixture_result=ok fixture=$name actual_exit=$status"
}

if [ ! -x "$WHOATHERE_BIN" ]; then
  echo "whoathere_binary_not_executable=$WHOATHERE_BIN" >&2
  exit 64
fi

if [ ! -x "$HELPER" ]; then
  echo "helper_not_executable=$HELPER" >&2
  exit 64
fi

"$WHOATHERE_BIN" vm health --state-dir "$STATE_DIR" --helper "$HELPER"

run_case clean_npm_lifecycle 0 npm ci
run_case npm_postinstall_canary_exfil 20 npm ci
run_case npm_prepare_remote_fetch 20 npm ci
run_case delayed_ci_canary 20 npm ci
run_case native_extension_canary 20 npm ci
run_case clean_pip_package 0 pip install .
run_case pypi_setup_py_canary 20 pip install .
run_case pypi_import_time_canary 20 pip install .
run_case direct_git_tarball_canary 20 npm ci

echo "detonation_fixture_validation=ok"
