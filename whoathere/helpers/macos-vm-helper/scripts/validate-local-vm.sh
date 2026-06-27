#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$SCRIPT_DIR/provision-command-lib.sh"
RESTORE_IMAGE=${1:-}
STATE_DIR=${2:-"$HOME/.whoathere/macos-vm-validation"}
HELPER_PATH="$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper"
BUNDLE_DIR="$STATE_DIR/bundle"
CONFIG_PATH="$BUNDLE_DIR/config.json"
MANIFEST_PATH="$BUNDLE_DIR/image.manifest"
DISK_PATH="$BUNDLE_DIR/disk.img"
AUXILIARY_STORAGE_PATH="$BUNDLE_DIR/auxiliary-storage"
HARDWARE_MODEL_PATH="$BUNDLE_DIR/hardware-model.bin"
MACHINE_IDENTIFIER_PATH="$BUNDLE_DIR/machine-identifier.bin"
GUEST_TOOLS_IMAGE_BASE="$BUNDLE_DIR/guest-tools"
GUEST_TOOLS_IMAGE="$GUEST_TOOLS_IMAGE_BASE.dmg"
GUEST_PROVISIONING_RECEIPT="$BUNDLE_DIR/guest-provisioning.json"
MEMORY_MIB=${WHOATHERE_VM_MEMORY_MIB:-6144}
DISK_GIB=${WHOATHERE_VM_DISK_GIB:-64}
HEALTH_ATTEMPTS=${WHOATHERE_VM_HEALTH_ATTEMPTS:-30}
HEALTH_INTERVAL_SECONDS=${WHOATHERE_VM_HEALTH_INTERVAL_SECONDS:-10}

installed_bundle_complete() {
  for path in \
    "$CONFIG_PATH" \
    "$MANIFEST_PATH" \
    "$DISK_PATH" \
    "$AUXILIARY_STORAGE_PATH" \
    "$HARDWARE_MODEL_PATH" \
    "$MACHINE_IDENTIFIER_PATH"
  do
    [ -e "$path" ] || return 1
  done
  return 0
}

installed_bundle_partial() {
  [ -d "$BUNDLE_DIR" ] || return 1
  installed_bundle_complete && return 1
  return 0
}

run_status_smoke() {
  set +e
  STATUS_OUTPUT=$("$HELPER_PATH" status --state-dir "$STATE_DIR" --json)
  STATUS_EXIT=$?
  set -e
  printf '%s\n' "$STATUS_OUTPUT"
  case "$STATUS_EXIT" in
    0)
      ;;
    20)
      case "$STATUS_OUTPUT" in
        *signature_verification_not_implemented*)
          echo "status_signature_verification_pending=true"
          ;;
        *)
          exit "$STATUS_EXIT"
          ;;
      esac
      ;;
    *)
      exit "$STATUS_EXIT"
      ;;
  esac
}

require_guest_provisioning() {
  if [ -f "$GUEST_PROVISIONING_RECEIPT" ]; then
    return
  fi

  echo "guest_readiness_agent_not_provisioned=true" >&2
  echo "provision_guest_first=$(whoathere_reprovision_command "$HELPER_ROOT" "$STATE_DIR")" >&2
  echo "rerun_validation_after_provisioning=$0 $RESTORE_IMAGE $STATE_DIR" >&2
  exit 20
}

poll_guest_health() {
  ATTEMPT=1
  while [ "$ATTEMPT" -le "$HEALTH_ATTEMPTS" ]; do
    set +e
    HEALTH_OUTPUT=$("$HELPER_PATH" health --state-dir "$STATE_DIR" --json)
    HEALTH_EXIT=$?
    set -e
    printf 'health_attempt=%s exit=%s\n%s\n' "$ATTEMPT" "$HEALTH_EXIT" "$HEALTH_OUTPUT"
    case "$HEALTH_EXIT" in
      0)
        return 0
        ;;
      20)
        ;;
      *)
        return "$HEALTH_EXIT"
        ;;
    esac
    ATTEMPT=$((ATTEMPT + 1))
    sleep "$HEALTH_INTERVAL_SECONDS"
  done
  return 20
}

if [ -z "$RESTORE_IMAGE" ]; then
  echo "usage: $0 /absolute/path/to/macos-restore.ipsw [state-dir]" >&2
  echo "   or: $0 --fetch-latest-restore-image [state-dir]" >&2
  exit 64
fi

FETCH_LATEST=false
if [ "$RESTORE_IMAGE" = "--fetch-latest-restore-image" ]; then
  FETCH_LATEST=true
else
  case "$RESTORE_IMAGE" in
    /*) ;;
    *)
      echo "restore_image_must_be_absolute=$RESTORE_IMAGE" >&2
      exit 64
      ;;
  esac

  if [ ! -f "$RESTORE_IMAGE" ] && ! installed_bundle_complete; then
    echo "restore_image_not_found=$RESTORE_IMAGE" >&2
    exit 64
  fi
fi

cd "$HELPER_ROOT"
swift test
./scripts/sign-local-helper.sh "$HELPER_PATH"

if installed_bundle_partial; then
  echo "bundle_partial=true" >&2
  echo "reset_or_prune_first=$HELPER_PATH reset --state-dir $STATE_DIR --execute --json" >&2
  exit 20
fi

if installed_bundle_complete; then
  echo "existing_bundle_reuse=true"
elif [ "$FETCH_LATEST" = true ]; then
  "$HELPER_PATH" init \
    --state-dir "$STATE_DIR" \
    --fetch-latest-restore-image \
    --memory-mib "$MEMORY_MIB" \
    --disk-gib "$DISK_GIB" \
    --execute \
    --json
else
  "$HELPER_PATH" init \
    --state-dir "$STATE_DIR" \
    --restore-image "$RESTORE_IMAGE" \
    --memory-mib "$MEMORY_MIB" \
    --disk-gib "$DISK_GIB" \
    --execute \
    --json
fi

mkdir -p "$(dirname -- "$GUEST_TOOLS_IMAGE")"
rm -f "$GUEST_TOOLS_IMAGE"
hdiutil create \
  -quiet \
  -srcfolder "$HELPER_ROOT/guest-agent" \
  -format UFBI \
  -volname WhoaThereGuestTools \
  "$GUEST_TOOLS_IMAGE_BASE"
test -s "$GUEST_TOOLS_IMAGE"
echo "guest_tools_image=$GUEST_TOOLS_IMAGE"

run_status_smoke
require_guest_provisioning
"$HELPER_PATH" start --state-dir "$STATE_DIR" --execute --json
set +e
poll_guest_health
HEALTH_EXIT=$?
set -e
"$HELPER_PATH" suspend --state-dir "$STATE_DIR" --execute --json
case "$HEALTH_EXIT" in
  0)
    echo "guest_health_proven=true"
    ;;
  20)
    echo "guest_health_pending=true"
    echo "verify guest provisioning receipt and guest readiness daemon logs"
    ;;
  *)
    echo "unexpected_health_exit=$HEALTH_EXIT" >&2
    exit "$HEALTH_EXIT"
    ;;
esac
run_status_smoke
