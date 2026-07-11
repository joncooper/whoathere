#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --preflight /absolute/state-dir" >&2
  echo "       $0 --execute /absolute/state-dir /absolute/new-evidence-dir" >&2
  exit 64
}

[ "$#" -ge 2 ] || usage
MODE=$1
STATE=$2
shift 2
case "$STATE" in
  /*) ;;
  *) usage ;;
esac
case "$MODE:$#" in
  --preflight:0) EVIDENCE_DIR="" ;;
  --execute:1)
    EVIDENCE_DIR=$1
    case "$EVIDENCE_DIR" in
      /*) ;;
      *) usage ;;
    esac
    ;;
  *) usage ;;
esac

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUNDLE="$STATE/bundle"
HELPER=${WHOATHERE_MACOS_VM_HELPER_BINARY:-"$REPO_ROOT/whoathere/helpers/macos-vm-helper/.build/release/whoathere-macos-vm-helper"}
GENERATOR=${WHOATHERE_MEASURED_WHEEL_GENERATOR_BINARY:-"$REPO_ROOT/whoathere/target/release/examples/measured_inert_wheel_launch"}

preflight_reason=""
if [ ! -d "$STATE" ] || [ -L "$STATE" ]; then
  preflight_reason="wheel_vm_qualification_state_missing_or_unsafe"
elif [ ! -d "$BUNDLE" ] || [ -L "$BUNDLE" ]; then
  preflight_reason="wheel_vm_qualification_bundle_missing_or_unsafe"
else
  for name in disk.img auxiliary-storage hardware-model.bin machine-identifier.bin \
    wheel-supervisor-public-key.bin wheel-supervisor-provisioning.json; do
    if [ ! -f "$BUNDLE/$name" ] || [ -L "$BUNDLE/$name" ]; then
      preflight_reason="wheel_vm_qualification_base_material_missing_or_unsafe"
      break
    fi
  done
fi
if [ -z "$preflight_reason" ] && { [ ! -x "$HELPER" ] || [ -L "$HELPER" ]; }; then
  preflight_reason="wheel_vm_qualification_helper_missing_or_unsafe"
fi
if [ -z "$preflight_reason" ] && { [ ! -x "$GENERATOR" ] || [ -L "$GENERATOR" ]; }; then
  preflight_reason="wheel_vm_qualification_generator_missing_or_unsafe"
fi
if [ -z "$preflight_reason" ] && [ -f "$BUNDLE/runtime.pid" ]; then
  RUNTIME_PID=$(cat "$BUNDLE/runtime.pid" 2>/dev/null || true)
  case "$RUNTIME_PID" in
    ''|*[!0-9]*) preflight_reason="wheel_vm_qualification_runtime_state_invalid" ;;
    *)
      if kill -0 "$RUNTIME_PID" 2>/dev/null; then
        preflight_reason="wheel_vm_qualification_vm_must_be_stopped"
      fi
      ;;
  esac
fi
if [ -z "$preflight_reason" ]; then
  EXPECTED_UID=$(id -u)
  for path in "$STATE" "$BUNDLE" "$BUNDLE/disk.img" \
    "$BUNDLE/auxiliary-storage" "$BUNDLE/hardware-model.bin" \
    "$BUNDLE/machine-identifier.bin" "$BUNDLE/wheel-supervisor-public-key.bin" \
    "$BUNDLE/wheel-supervisor-provisioning.json" "$HELPER" "$GENERATOR"; do
    if [ "$(stat -f '%u' "$path")" -ne "$EXPECTED_UID" ] \
      || [ $((0$(stat -f '%Lp' "$path") & 0022)) -ne 0 ]; then
      preflight_reason="wheel_vm_qualification_owner_or_mode_unsafe"
      break
    fi
  done
fi

if [ -n "$preflight_reason" ]; then
  echo "wheel_vm_qualification_preflight=false"
  echo "reason_code=$preflight_reason"
  exit 20
fi
if [ "$MODE" = "--preflight" ]; then
  echo "wheel_vm_qualification_preflight=true"
  echo "artifact_kind=generated_inert_wheel"
  echo "network_device_count=0"
  echo "package_execution_enabled=false"
  echo "sync_back_enabled=false"
  exit 0
fi

if [ -e "$EVIDENCE_DIR" ] || [ -L "$EVIDENCE_DIR" ]; then
  echo "reason_code=wheel_vm_qualification_evidence_path_exists" >&2
  exit 64
fi
EVIDENCE_PARENT=$(dirname -- "$EVIDENCE_DIR")
if [ ! -d "$EVIDENCE_PARENT" ] || [ -L "$EVIDENCE_PARENT" ] \
  || [ "$(stat -f '%u' "$EVIDENCE_PARENT")" -ne "$(id -u)" ] \
  || [ $((0$(stat -f '%Lp' "$EVIDENCE_PARENT") & 0022)) -ne 0 ]; then
  echo "reason_code=wheel_vm_qualification_evidence_parent_unsafe" >&2
  exit 64
fi
umask 077
mkdir "$EVIDENCE_DIR"
chmod 0700 "$EVIDENCE_DIR"

FRAME="$EVIDENCE_DIR/wheel.submission"
LAUNCH_MANIFEST="$EVIDENCE_DIR/wheel.launch.json"
GENERATOR_OUTPUT="$EVIDENCE_DIR/generator.txt"
HELPER_OUTPUT="$EVIDENCE_DIR/helper-result.json"
BASE_BEFORE="$EVIDENCE_DIR/base-before.sha256"
BASE_AFTER="$EVIDENCE_DIR/base-after.sha256"

shasum -a 256 "$BUNDLE/disk.img" "$BUNDLE/auxiliary-storage" > "$BASE_BEFORE"
"$GENERATOR" \
  --state-dir "$STATE" \
  --helper "$HELPER" \
  --submission-output "$FRAME" \
  --launch-manifest-output "$LAUNCH_MANIFEST" > "$GENERATOR_OUTPUT"
AUTHORITY_ID=$(sed -n 's/.*"authority_id":"\([^"]*\)".*/\1/p' "$LAUNCH_MANIFEST")
if [ -z "$AUTHORITY_ID" ]; then
  echo "reason_code=wheel_vm_qualification_authority_missing" >&2
  exit 70
fi

set +e
"$HELPER" wheel-run \
  --execute \
  --state-dir "$STATE" \
  --authority-id "$AUTHORITY_ID" \
  --json < "$FRAME" > "$HELPER_OUTPUT" 2>&1
HELPER_STATUS=$?
set -e
printf '%s\n' "$HELPER_STATUS" > "$EVIDENCE_DIR/helper-exit-code.txt"
shasum -a 256 "$BUNDLE/disk.img" "$BUNDLE/auxiliary-storage" > "$BASE_AFTER"
if [ "$HELPER_STATUS" -ne 0 ]; then
  echo "reason_code=wheel_vm_qualification_helper_failed" >&2
  exit 70
fi

grep -q '"schema_version" : "whoathere.macos_wheel_run_nonexecuting.v1"' "$HELPER_OUTPUT"
grep -q '"status" : "staged_no_execution"' "$HELPER_OUTPUT"
grep -q '"authority_consumed" : true' "$HELPER_OUTPUT"
grep -q '"authority_replay_state_persisted" : true' "$HELPER_OUTPUT"
grep -q '"network_device_count" : 0' "$HELPER_OUTPUT"
grep -q '"wheel_vsock_port" : 47080' "$HELPER_OUTPUT"
grep -q '"vm_start_succeeded" : true' "$HELPER_OUTPUT"
grep -q '"vm_stop_succeeded" : true' "$HELPER_OUTPUT"
grep -q '"guest_authentication_verified" : true' "$HELPER_OUTPUT"
grep -q '"guest_staging_receipt_verified" : true' "$HELPER_OUTPUT"
grep -q '"guest_staging_cleanup_succeeded" : true' "$HELPER_OUTPUT"
grep -q '"guest_channel_terminated" : true' "$HELPER_OUTPUT"
grep -q '"clone_cleanup_succeeded" : true' "$HELPER_OUTPUT"
grep -q '"package_execution_enabled" : false' "$HELPER_OUTPUT"
grep -q '"sync_back_enabled" : false' "$HELPER_OUTPUT"
cmp -s "$BASE_BEFORE" "$BASE_AFTER"

PENDING="$STATE/wheel-authorities/pending/$AUTHORITY_ID.json"
CONSUMED="$STATE/wheel-authorities/consumed/$AUTHORITY_ID.json"
[ ! -e "$PENDING" ]
[ -f "$CONSUMED" ]
if [ -d "$STATE/wheel-runs" ]; then
  [ -z "$(find "$STATE/wheel-runs" -mindepth 1 -print -quit)" ]
fi

echo "wheel_vm_qualification_passed=true"
echo "evidence_dir=$EVIDENCE_DIR"
echo "artifact_kind=generated_inert_wheel"
echo "package_execution_enabled=false"
echo "sync_back_enabled=false"
