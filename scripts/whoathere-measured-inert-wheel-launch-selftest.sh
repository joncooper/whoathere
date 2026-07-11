#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-measured-wheel-launch.XXXXXX")
cleanup() {
  case "$ROOT" in
    "${TMPDIR:-/tmp}"/whoathere-measured-wheel-launch.*) rm -rf "$ROOT" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

STATE="$ROOT/state"
BUNDLE="$STATE/bundle"
FRAME="$ROOT/wheel.submission"
LAUNCH_MANIFEST="$ROOT/wheel.launch.json"
mkdir -p "$BUNDLE"
chmod 0700 "$STATE" "$BUNDLE"
printf '%s' 'inert fake wheel disk' > "$BUNDLE/disk.img"
printf '%s' 'inert fake wheel auxiliary storage' > "$BUNDLE/auxiliary-storage"
printf '%s' 'deliberately invalid hardware model' > "$BUNDLE/hardware-model.bin"
printf '%s' 'deliberately invalid machine identifier' > "$BUNDLE/machine-identifier.bin"
dd if=/dev/zero of="$BUNDLE/wheel-supervisor-public-key.bin" bs=32 count=1 2>/dev/null
chmod 0600 "$BUNDLE"/*

digest_text() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

PUBLIC_KEY_DIGEST=$(shasum -a 256 "$BUNDLE/wheel-supervisor-public-key.bin" | awk '{print $1}')
SUPERVISOR_DIGEST=$(digest_text 'selftest wheel supervisor')
RUNNER_DIGEST=$(digest_text 'selftest wheel runner configuration')
PYTHON_DIGEST=$(digest_text 'selftest python executable')
PIP_DIGEST=$(digest_text 'selftest pip cli')
CLONE_DIGEST=$(digest_text 'whoathere.swift.fclonefileat.direct.v1')
PROTOCOL_DIGEST=$(digest_text 'whoathere.wheel_artifact_scenario.v1')
RECEIPT="$BUNDLE/wheel-supervisor-provisioning.json"
RECEIPT_LIB="$REPO_ROOT/whoathere/helpers/macos-vm-helper/scripts/wheel-supervisor-receipt-lib.sh"
. "$RECEIPT_LIB"
whoathere_render_wheel_supervisor_receipt \
  selftest-wheel-base \
  "sha256:$CLONE_DIGEST" \
  2 \
  "sha256:$PUBLIC_KEY_DIGEST" \
  "sha256:$PROTOCOL_DIGEST" \
  "sha256:$SUPERVISOR_DIGEST" \
  6144 \
  499 \
  499 \
  _whoatherepkg \
  "sha256:$PIP_DIGEST" \
  26.1.2 \
  "sha256:$PYTHON_DIGEST" \
  3.12.13 \
  "sha256:$RUNNER_DIGEST" > "$RECEIPT"
chmod 0600 "$RECEIPT"

HELPER="$REPO_ROOT/whoathere/helpers/macos-vm-helper/.build/debug/whoathere-macos-vm-helper"
GENERATOR="$REPO_ROOT/whoathere/target/debug/examples/measured_inert_wheel_launch"
[ -x "$HELPER" ]
[ -x "$GENERATOR" ]
OUTPUT=$(
  "$GENERATOR" \
    --state-dir "$STATE" \
    --helper "$HELPER" \
    --submission-output "$FRAME" \
    --launch-manifest-output "$LAUNCH_MANIFEST"
)
printf '%s\n' "$OUTPUT" | grep -q '^measured_inert_wheel_launch_prepared=true$'
printf '%s\n' "$OUTPUT" | grep -q '^package_execution_enabled=false$'
printf '%s\n' "$OUTPUT" | grep -q '^sync_back_enabled=false$'
[ "$(stat -f '%Lp' "$FRAME")" = "600" ]
[ "$(stat -f '%Lp' "$LAUNCH_MANIFEST")" = "600" ]
AUTHORITY_ID=$(
  sed -n 's/.*"authority_id":"\([^"]*\)".*/\1/p' "$LAUNCH_MANIFEST"
)
[ -n "$AUTHORITY_ID" ]
PENDING="$STATE/wheel-authorities/pending/$AUTHORITY_ID.json"
CONSUMED="$STATE/wheel-authorities/consumed/$AUTHORITY_ID.json"
[ -f "$PENDING" ]
[ ! -e "$CONSUMED" ]

set +e
OUTPUT=$(
  "$HELPER" wheel-run \
    --execute \
    --state-dir "$STATE" \
    --authority-id "$AUTHORITY_ID" \
    --json < "$FRAME" 2>&1
)
STATUS=$?
set -e
[ "$STATUS" -eq 65 ]
printf '%s\n' "$OUTPUT" | grep -q 'artifact_run_virtualization_metadata_invalid'
printf '%s\n' "$OUTPUT" | grep -q '"authority_consumed" : true'
printf '%s\n' "$OUTPUT" | grep -q '"authority_replay_state_persisted" : true'
printf '%s\n' "$OUTPUT" | grep -q '"clone_cleanup_succeeded" : true'
printf '%s\n' "$OUTPUT" | grep -q '"package_execution_enabled" : false'
printf '%s\n' "$OUTPUT" | grep -q '"sync_back_enabled" : false'
[ ! -e "$PENDING" ]
[ -f "$CONSUMED" ]
if [ -d "$STATE/wheel-runs" ]; then
  [ -z "$(find "$STATE/wheel-runs" -mindepth 1 -print -quit)" ]
fi

set +e
REPLAY_OUTPUT=$(
  "$HELPER" wheel-run \
    --execute \
    --state-dir "$STATE" \
    --authority-id "$AUTHORITY_ID" \
    --json < "$FRAME" 2>&1
)
REPLAY_STATUS=$?
set -e
[ "$REPLAY_STATUS" -eq 65 ]
printf '%s\n' "$REPLAY_OUTPUT" | grep -q 'wheel_run_authority_already_consumed'
printf '%s\n' "$REPLAY_OUTPUT" | grep -q '"package_execution_enabled" : false'

echo "measured_inert_wheel_launch_selftest=passed"
