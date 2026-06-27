#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPO_ROOT=$(CDPATH= cd -- "$HELPER_ROOT/../../.." && pwd)
. "$SCRIPT_DIR/provision-command-lib.sh"
RUST_WORKSPACE="$REPO_ROOT/whoathere"

if [ -x "$RUST_WORKSPACE/target/debug/whoathere" ]; then
  DEFAULT_WHOATHERE_BIN="$RUST_WORKSPACE/target/debug/whoathere"
else
  DEFAULT_WHOATHERE_BIN="$REPO_ROOT/target/debug/whoathere"
fi

WHOATHERE_BIN=${WHOATHERE_BIN:-"$DEFAULT_WHOATHERE_BIN"}
HELPER=${WHOATHERE_MACOS_VM_HELPER:-"$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper"}
STATE_DIR=${WHOATHERE_VM_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}
WORK_ROOT=${TMPDIR:-/tmp}/whoathere-project-detonation.$$

cleanup() {
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

receipt_agent_digest() {
  receipt="$STATE_DIR/bundle/guest-provisioning.json"
  if [ ! -f "$receipt" ]; then
    echo ""
    return
  fi
  sed -n 's/.*"agent_sha256"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$receipt" | head -n 1
}

current_agent_digest() {
  agent_binary="$WORK_ROOT/whoathere-guest-ready"
  cc -O2 -Wall -Wextra -target arm64-apple-macos13 \
    -o "$agent_binary" \
    "$HELPER_ROOT/guest-agent/whoathere-guest-ready.c"
  /usr/bin/codesign --force --sign - "$agent_binary" >/dev/null 2>&1 || true
  digest=$(shasum -a 256 "$agent_binary" | awk '{print $1}')
  printf 'sha256:%s\n' "$digest"
}

require_current_guest_agent() {
  provisioned_digest=$(receipt_agent_digest)
  expected_digest=$(current_agent_digest)
  if [ -z "$provisioned_digest" ]; then
    echo "guest_agent_provisioning_receipt_missing=true" >&2
    echo "reprovision_command=$(whoathere_reprovision_command "$HELPER_ROOT" "$STATE_DIR")" >&2
    exit 64
  fi
  if [ "$provisioned_digest" != "$expected_digest" ]; then
    echo "guest_agent_digest_mismatch=true" >&2
    echo "provisioned_guest_agent_digest=$provisioned_digest" >&2
    echo "expected_guest_agent_digest=$expected_digest" >&2
    echo "vm_must_be_stopped_before_reprovision=true" >&2
    echo "reprovision_command=$(whoathere_reprovision_command "$HELPER_ROOT" "$STATE_DIR")" >&2
    exit 64
  fi
}

write_clean_project() {
  project=$1
  module=${2:-whoathere_clean}
  mkdir -p "$project"
  cat > "$project/setup.py" <<EOF
from setuptools import setup
setup(name="whoathere-clean", version="0.0.1", py_modules=["$module"])
EOF
  cat > "$project/$module.py" <<EOF
VALUE = "clean"
EOF
}

write_setup_canary_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/setup.py" <<'EOF'
from setuptools import setup
import os
import pathlib
if os.environ.get("PYPI_TOKEN"):
    pathlib.Path("canary-read.marker").write_text("1")
setup(name="whoathere-setup-canary", version="0.0.1", py_modules=["whoathere_setup_canary"])
EOF
  cat > "$project/whoathere_setup_canary.py" <<'EOF'
VALUE = "setup-canary"
EOF
}

write_pep517_canary_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/pyproject.toml" <<'EOF'
[build-system]
requires = []
build-backend = "whoathere_backend"
backend-path = ["."]
EOF
  cat > "$project/whoathere_backend.py" <<'EOF'
import os
import pathlib
import zipfile

DIST = "whoathere_pep517_canary-0.0.1.dist-info"
METADATA = "Metadata-Version: 2.1\nName: whoathere-pep517-canary\nVersion: 0.0.1\n"
WHEEL = "Wheel-Version: 1.0\nGenerator: whoathere\nRoot-Is-Purelib: true\nTag: py3-none-any\n"

def _mark():
    if os.environ.get("PYPI_TOKEN"):
        pathlib.Path("canary-read.marker").write_text("1")

def get_requires_for_build_wheel(config_settings=None):
    _mark()
    return []

def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    _mark()
    dist = pathlib.Path(metadata_directory) / DIST
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(METADATA)
    (dist / "WHEEL").write_text(WHEEL)
    return DIST

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _mark()
    wheel_name = "whoathere_pep517_canary-0.0.1-py3-none-any.whl"
    path = pathlib.Path(wheel_directory) / wheel_name
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("whoathere_pep517_canary.py", "VALUE = 'pep517'\n")
        archive.writestr(DIST + "/METADATA", METADATA)
        archive.writestr(DIST + "/WHEEL", WHEEL)
        archive.writestr(DIST + "/RECORD", "")
    return wheel_name
EOF
  cat > "$project/whoathere_pep517_canary.py" <<'EOF'
VALUE = "pep517"
EOF
}

write_import_canary_project() {
  project=$1
  mkdir -p "$project"
  cat > "$project/setup.py" <<'EOF'
from setuptools import setup
setup(name="whoathere-import-canary", version="0.0.1", py_modules=["whoathere_import_canary"])
EOF
  cat > "$project/whoathere_import_canary.py" <<'EOF'
import os
import pathlib
if os.environ.get("PYPI_TOKEN"):
    pathlib.Path("import-canary-read.marker").write_text("1")
VALUE = "import-canary"
EOF
}

write_pth_canary_project() {
  project=$1
  write_clean_project "$project" whoathere_pth_canary
  cat > "$project/whoathere_hook.pth" <<'EOF'
import os,pathlib; pathlib.Path("pth-canary-read.marker").write_text("1") if os.environ.get("PYPI_TOKEN") else None
EOF
}

write_package_data_project() {
  project=$1
  mkdir -p "$project/whoathere_pkg/data"
  cat > "$project/setup.py" <<'EOF'
from setuptools import setup
setup(
    name="whoathere-package-data",
    version="0.0.1",
    packages=["whoathere_pkg"],
    package_data={"whoathere_pkg": ["data/schema.json"]},
)
EOF
  cat > "$project/whoathere_pkg/__init__.py" <<'EOF'
VALUE = "package-data"
EOF
  cat > "$project/whoathere_pkg/data/schema.json" <<'EOF'
{"safe": true}
EOF
  cat > "$project/README.md" <<'EOF'
root-level readme should not be mirrored as package data
EOF
}

write_native_marker_project() {
  project=$1
  write_package_data_project "$project"
  printf 'not-a-real-shared-object\n' > "$project/whoathere_pkg/native.so"
}

assert_no_host_markers() {
  project=$1
  if find "$project" \( -name 'canary-read.marker' -o -name 'import-canary-read.marker' -o -name 'pth-canary-read.marker' -o -name target \) -print | grep . >/dev/null; then
    echo "host_project_modified_or_marker_present=$project" >&2
    find "$project" \( -name 'canary-read.marker' -o -name 'import-canary-read.marker' -o -name 'pth-canary-read.marker' -o -name target \) -print >&2
    exit 1
  fi
}

run_project_case() {
  name=$1
  expected=$2
  project=$3
  shift 3

  echo "project_case=$name expected_exit=$expected"
  set +e
  output=$("$WHOATHERE_BIN" vm detonate \
    --workspace "$project" \
    --state-dir "$STATE_DIR" \
    --helper "$HELPER" \
    --timeout-seconds 120 \
    --execute \
    pip -- "$@" 2>&1)
  status=$?
  set -e
  printf '%s\n' "$output"
  if [ "$status" -ne "$expected" ]; then
    echo "project_case_result=failed name=$name actual_exit=$status expected_exit=$expected" >&2
    exit 1
  fi
  if [ "$expected" -eq 0 ]; then
    case "$output" in
      *allow_observed_clean*) ;;
      *)
        echo "project_case_result=failed name=$name expected_verdict_missing=allow_observed_clean" >&2
        exit 1
        ;;
    esac
  fi
  assert_no_host_markers "$project"
  echo "project_case_result=ok name=$name actual_exit=$status"
}

run_fail_closed_gate() {
  name=$1
  project=$2
  shift 2

  echo "gate_case=$name expected_exit=20"
  set +e
  output=$("$WHOATHERE_BIN" vm detonate \
    --workspace "$project" \
    --state-dir "$STATE_DIR" \
    --helper "$HELPER" \
    --timeout-seconds 120 \
    --execute \
    pip -- "$@" 2>&1)
  status=$?
  set -e
  printf '%s\n' "$output"
  if [ "$status" -ne 20 ]; then
    echo "gate_case_result=failed name=$name actual_exit=$status expected_exit=20" >&2
    exit 1
  fi
  case "$output" in
    *helper_invoked=false*|*"\"helper\": null"*) ;;
    *)
      echo "gate_case_result=failed name=$name helper_was_invoked_or_not_proven=false" >&2
      exit 1
      ;;
  esac
  assert_no_host_markers "$project"
  echo "gate_case_result=ok name=$name actual_exit=$status"
}

run_dry_run_contains() {
  name=$1
  project=$2
  expected=$3
  shift 3

  echo "dry_run_case=$name expected_text=$expected"
  output=$("$WHOATHERE_BIN" vm detonate \
    --workspace "$project" \
    --state-dir "$STATE_DIR" \
    --helper "$HELPER" \
    pip -- "$@")
  printf '%s\n' "$output"
  case "$output" in
    *"$expected"*) ;;
    *)
      echo "dry_run_case_result=failed name=$name expected_text_missing=$expected" >&2
      exit 1
      ;;
  esac
  echo "dry_run_case_result=ok name=$name"
}

require_tooling
mkdir -p "$WORK_ROOT"
require_current_guest_agent

"$WHOATHERE_BIN" vm health --state-dir "$STATE_DIR" --helper "$HELPER"

clean="$WORK_ROOT/clean"
write_clean_project "$clean"
run_project_case clean_project 0 "$clean" install .

requirements_clean="$WORK_ROOT/requirements-clean"
write_clean_project "$requirements_clean"
printf '.\n' > "$requirements_clean/requirements.txt"
run_project_case requirements_local_project 0 "$requirements_clean" install -r requirements.txt

package_data="$WORK_ROOT/package-data"
write_package_data_project "$package_data"
run_dry_run_contains package_data_included "$package_data" "mirror_package_data_file_count=1" install .
run_project_case package_data_project 0 "$package_data" install .

setup_canary="$WORK_ROOT/setup-canary"
write_setup_canary_project "$setup_canary"
run_project_case setup_canary 20 "$setup_canary" install .

pep517_canary="$WORK_ROOT/pep517-canary"
write_pep517_canary_project "$pep517_canary"
run_project_case pep517_canary 20 "$pep517_canary" install .

import_canary="$WORK_ROOT/import-canary"
write_import_canary_project "$import_canary"
run_project_case import_canary 20 "$import_canary" install .

pth_canary="$WORK_ROOT/pth-canary"
write_pth_canary_project "$pth_canary"
run_project_case pth_canary 20 "$pth_canary" install .

unsafe_requirements="$WORK_ROOT/unsafe-requirements"
write_clean_project "$unsafe_requirements"
printf 'requests\n' > "$unsafe_requirements/requirements.txt"
run_fail_closed_gate public_requirement "$unsafe_requirements" install -r requirements.txt
printf 'git+https://example.invalid/repo.git\n' > "$unsafe_requirements/requirements.txt"
run_fail_closed_gate vcs_requirement "$unsafe_requirements" install -r requirements.txt
printf 'https://example.invalid/pkg-0.0.1.tar.gz\n' > "$unsafe_requirements/requirements.txt"
run_fail_closed_gate direct_url_requirement "$unsafe_requirements" install -r requirements.txt
printf '%s\n' '-e .' > "$unsafe_requirements/requirements.txt"
run_fail_closed_gate editable_requirement "$unsafe_requirements" install -r requirements.txt
printf -- '-r ../outside.txt\n' > "$unsafe_requirements/requirements.txt"
run_fail_closed_gate traversal_requirement "$unsafe_requirements" install -r requirements.txt

native_marker="$WORK_ROOT/native-marker"
write_native_marker_project "$native_marker"
run_fail_closed_gate native_marker "$native_marker" install .

secret_project="$WORK_ROOT/secret-project"
write_clean_project "$secret_project"
printf 'password=real-secret-value\n' > "$secret_project/.pypirc"
run_dry_run_contains secret_exclusion "$secret_project" "mirror_secret_exclusion_count=1" install .
secret_output=$("$WHOATHERE_BIN" vm detonate --workspace "$secret_project" --state-dir "$STATE_DIR" --helper "$HELPER" pip -- install .)
case "$secret_output" in
  *real-secret-value*)
    echo "secret_value_leaked_in_output=true" >&2
    exit 1
    ;;
esac

symlink_project="$WORK_ROOT/symlink-project"
write_clean_project "$symlink_project"
printf 'outside-secret\n' > "$WORK_ROOT/outside.txt"
ln -s "$WORK_ROOT/outside.txt" "$symlink_project/escape.txt" 2>/dev/null || true
run_dry_run_contains symlink_escape "$symlink_project" "detonation_workspace_symlink_escape_blocked" install .

large_project="$WORK_ROOT/large-project"
write_clean_project "$large_project"
dd if=/dev/zero of="$large_project/large_module.py" bs=1024 count=130 >/dev/null 2>&1
run_dry_run_contains large_file "$large_project" "detonation_workspace_large_file_excluded" install .

echo "project_detonation_validation=ok"
