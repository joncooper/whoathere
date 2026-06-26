#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
HELPER_PATH=${1:-"$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper"}
ENTITLEMENTS_PATH="$HELPER_ROOT/whoathere-macos-vm-helper.entitlements"
SIGN_IDENTITY=${WHOATHERE_CODESIGN_IDENTITY:--}

if [ ! -f "$HELPER_PATH" ]; then
  echo "helper_not_found=$HELPER_PATH" >&2
  exit 64
fi

if [ ! -f "$ENTITLEMENTS_PATH" ]; then
  echo "entitlements_not_found=$ENTITLEMENTS_PATH" >&2
  exit 64
fi

/usr/bin/codesign \
  --force \
  --options runtime \
  --entitlements "$ENTITLEMENTS_PATH" \
  --sign "$SIGN_IDENTITY" \
  "$HELPER_PATH"

/usr/bin/codesign --verify --strict --verbose=2 "$HELPER_PATH"
/usr/bin/codesign -d --entitlements :- "$HELPER_PATH"
