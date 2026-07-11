#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-measured-submission-selftest.XXXXXX")
cleanup() {
  case "$ROOT" in
    "${TMPDIR:-/tmp}"/whoathere-measured-submission-selftest.*) rm -rf "$ROOT" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

STATE="$ROOT/state"
BUNDLE="$STATE/bundle"
FRAME="$ROOT/submission.frame"
mkdir -p "$BUNDLE"
chmod 0700 "$STATE" "$BUNDLE"
printf '%s' 'inert fake disk' > "$BUNDLE/disk.img"
printf '%s' 'inert fake auxiliary storage' > "$BUNDLE/auxiliary-storage"
printf '%s' 'deliberately invalid hardware model' > "$BUNDLE/hardware-model.bin"
printf '%s' 'deliberately invalid machine identifier' > "$BUNDLE/machine-identifier.bin"
dd if=/dev/zero of="$BUNDLE/artifact-supervisor-public-key.bin" bs=32 count=1 2>/dev/null
chmod 0600 "$BUNDLE"/*

digest_text() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

PUBLIC_KEY_DIGEST=$(shasum -a 256 "$BUNDLE/artifact-supervisor-public-key.bin" | awk '{print $1}')
SUPERVISOR_DIGEST=$(digest_text 'selftest supervisor')
RUNNER_DIGEST=$(digest_text 'selftest runner configuration')
NODE_DIGEST=$(digest_text 'selftest node')
NPM_DIGEST=$(digest_text 'selftest npm cli')
CLONE_DIGEST=$(digest_text 'whoathere.swift.fclonefileat.direct.v1')
RECEIPT="$BUNDLE/artifact-supervisor-provisioning.json"
printf '%s' "{\"artifact_vsock_port\":\"47079\",\"base_generation_id\":\"selftest-base\",\"clone_implementation_sha256\":\"sha256:$CLONE_DIGEST\",\"cpu_count\":\"2\",\"guest_auth_public_key_sha256\":\"sha256:$PUBLIC_KEY_DIGEST\",\"guest_supervisor_sha256\":\"sha256:$SUPERVISOR_DIGEST\",\"memory_mib\":\"6144\",\"node_executable_sha256\":\"sha256:$NODE_DIGEST\",\"node_version\":\"22.17.0\",\"npm_cli_sha256\":\"sha256:$NPM_DIGEST\",\"npm_version\":\"11.18.0\",\"package_execution_enabled\":false,\"package_gid\":\"502\",\"package_uid\":\"502\",\"package_username\":\"_whoatherepkg\",\"runner_configuration_sha256\":\"sha256:$RUNNER_DIGEST\",\"schema_version\":\"whoathere.artifact_supervisor_provisioning.v1\",\"sync_back_enabled\":false}" > "$RECEIPT"
chmod 0600 "$RECEIPT"

HELPER="$REPO_ROOT/whoathere/helpers/macos-vm-helper/.build/debug/whoathere-macos-vm-helper"
GENERATOR="$REPO_ROOT/whoathere/target/debug/examples/measured_inert_artifact_submission"
[ -x "$HELPER" ]
[ -x "$GENERATOR" ]
"$GENERATOR" --state-dir "$STATE" --helper "$HELPER" > "$FRAME"

set +e
OUTPUT=$("$HELPER" artifact-run --execute --state-dir "$STATE" --json < "$FRAME" 2>&1)
STATUS=$?
set -e
[ "$STATUS" -eq 65 ]
printf '%s\n' "$OUTPUT" | grep -q 'artifact_run_virtualization_metadata_invalid'
printf '%s\n' "$OUTPUT" | grep -q '"clone_cleanup_succeeded" : true'
printf '%s\n' "$OUTPUT" | grep -q '"package_execution_enabled" : false'
if [ -d "$STATE/artifact-runs" ]; then
  [ -z "$(find "$STATE/artifact-runs" -mindepth 1 -print -quit)" ]
fi

echo "measured_inert_submission_selftest=passed"
