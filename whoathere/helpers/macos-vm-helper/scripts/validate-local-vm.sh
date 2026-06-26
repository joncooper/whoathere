#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RESTORE_IMAGE=${1:-}
STATE_DIR=${2:-"$HOME/.whoathere/macos-vm-validation"}
HELPER_PATH="$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper"
GUEST_TOOLS_IMAGE_BASE="$STATE_DIR/bundle/guest-tools"
GUEST_TOOLS_IMAGE="$GUEST_TOOLS_IMAGE_BASE.dmg"
GUEST_PROVISIONING_RECEIPT="$STATE_DIR/bundle/guest-provisioning.json"
MEMORY_MIB=${WHOATHERE_VM_MEMORY_MIB:-6144}
DISK_GIB=${WHOATHERE_VM_DISK_GIB:-64}

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
  echo "provision_guest_first=sudo $HELPER_ROOT/scripts/provision-guest-readiness.sh $STATE_DIR" >&2
  echo "rerun_validation_after_provisioning=$0 $RESTORE_IMAGE $STATE_DIR" >&2
  exit 20
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

  if [ ! -f "$RESTORE_IMAGE" ]; then
    echo "restore_image_not_found=$RESTORE_IMAGE" >&2
    exit 64
  fi
fi

cd "$HELPER_ROOT"
swift test
./scripts/sign-local-helper.sh "$HELPER_PATH"

if [ "$FETCH_LATEST" = true ]; then
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
"$HELPER_PATH" health --state-dir "$STATE_DIR" --json
HEALTH_EXIT=$?
set -e
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
"$HELPER_PATH" suspend --state-dir "$STATE_DIR" --execute --json
run_status_smoke
