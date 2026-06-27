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

run_case_one_of() {
  name=$1
  expected_list=$2
  tool=$3
  shift 3

  echo "fixture=$name expected_exit_one_of=$expected_list tool=$tool"
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
  case ",$expected_list," in
    *,"$status",*)
      echo "fixture_result=ok fixture=$name actual_exit=$status"
      ;;
    *)
      echo "fixture_result=failed fixture=$name actual_exit=$status expected_exit_one_of=$expected_list" >&2
      exit 1
      ;;
  esac
}

run_clean_case_one_of() {
  name=$1
  expected_list=$2
  tool=$3
  shift 3

  echo "fixture=$name expected_exit_one_of=$expected_list tool=$tool clean_candidate=true"
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
  case ",$expected_list," in
    *,"$status",*)
      if [ "$status" -eq 0 ]; then
        CLEAN_EXECUTION_SUCCEEDED=1
      fi
      echo "fixture_result=ok fixture=$name actual_exit=$status"
      ;;
    *)
      echo "fixture_result=failed fixture=$name actual_exit=$status expected_exit_one_of=$expected_list" >&2
      exit 1
      ;;
  esac
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

CLEAN_EXECUTION_SUCCEEDED=0

run_clean_case_one_of clean_npm_lifecycle 0,20 npm ci
run_case npm_postinstall_canary_exfil 20 npm ci
run_case npm_prepare_remote_fetch 20 npm ci
run_case npm_darwin_only_payload 20 npm ci
run_case npm_bin_token_theft 20 npm exec whoathere-fixture
run_case delayed_ci_canary 20 npm ci
run_case dns_tunneling_canary 20 npm ci
run_case https_exfil_canary 20 npm ci
run_case api_compatible_canary_theft 20 npm ci
run_case native_extension_canary 20 npm ci
run_case npm_transitive_malicious_dependency 20 npm ci
run_clean_case_one_of clean_pip_package 0,20 pip install .
if [ "$CLEAN_EXECUTION_SUCCEEDED" -ne 1 ]; then
  echo "clean_fixture_execution_missing=true" >&2
  echo "expected_at_least_one_clean_npm_or_pip_fixture_exit_0=true" >&2
  exit 1
fi
run_case pypi_pep517_canary 20 pip install .
run_case pypi_setup_py_canary 20 pip install .
run_case pypi_import_time_canary 20 pip install .
run_case python_pth_startup_hook 20 pip install .
run_case api_compatible_canary_theft 20 pip install .
run_case direct_git_tarball_canary 20 npm ci
run_case direct_url_vcs_editable 20 pip install .
run_case binary_wheel_native_marker 20 pip install .
run_case_one_of clean_pip_package 0,20 uv pip install .
run_case_one_of uv_unpinned_dependency 20 uv sync

echo "detonation_fixture_validation=ok"
