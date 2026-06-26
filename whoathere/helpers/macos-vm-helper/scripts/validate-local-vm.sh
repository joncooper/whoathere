#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RESTORE_IMAGE=${1:-}
STATE_DIR=${2:-"$HOME/.whoathere/macos-vm-validation"}
HELPER_PATH="$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper"
GUEST_TOOLS_IMAGE_BASE="$STATE_DIR/bundle/guest-tools"
GUEST_TOOLS_IMAGE="$GUEST_TOOLS_IMAGE_BASE.dmg"

if [ -z "$RESTORE_IMAGE" ]; then
  echo "usage: $0 /absolute/path/to/macos-restore.ipsw [state-dir]" >&2
  exit 64
fi

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

cd "$HELPER_ROOT"
swift test
./scripts/sign-local-helper.sh "$HELPER_PATH"

"$HELPER_PATH" init \
  --state-dir "$STATE_DIR" \
  --restore-image "$RESTORE_IMAGE" \
  --execute \
  --json

mkdir -p "$(dirname -- "$GUEST_TOOLS_IMAGE")"
rm -f "$GUEST_TOOLS_IMAGE"
hdiutil create \
  -quiet \
  -fs HFS+ \
  -srcfolder "$HELPER_ROOT/guest-agent" \
  -format UDRO \
  -volname WhoaThereGuestTools \
  "$GUEST_TOOLS_IMAGE_BASE"
test -s "$GUEST_TOOLS_IMAGE"
echo "guest_tools_image=$GUEST_TOOLS_IMAGE"

"$HELPER_PATH" status --state-dir "$STATE_DIR" --json
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
    echo "copy, build, and run guest-agent/whoathere-guest-ready inside the guest to produce guest health"
    ;;
  *)
    echo "unexpected_health_exit=$HEALTH_EXIT" >&2
    exit "$HEALTH_EXIT"
    ;;
esac
"$HELPER_PATH" suspend --state-dir "$STATE_DIR" --execute --json
"$HELPER_PATH" status --state-dir "$STATE_DIR" --json
