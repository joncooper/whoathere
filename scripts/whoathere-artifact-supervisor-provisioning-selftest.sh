#!/bin/sh
set -eu

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-artifact-provision-selftest.XXXXXX")
cleanup() {
  case "$ROOT" in
    "${TMPDIR:-/tmp}"/whoathere-artifact-provision-selftest.*) rm -rf "$ROOT" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

STATE="$ROOT/state"
BIN="$ROOT/bin"
mkdir -p "$STATE/bundle" "$BIN"
chmod 0700 "$STATE" "$BIN"
: > "$STATE/bundle/disk.img"
for name in whoathere-artifact-supervisor whoathere-artifact-supervisor-keygen; do
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$BIN/$name"
  chmod 0700 "$BIN/$name"
done

PROVISIONER="$(CDPATH= cd -- "$(dirname -- "$0")/../whoathere/helpers/macos-vm-helper/scripts" && pwd)/provision-artifact-supervisor.sh"
OUTPUT=$(WHOATHERE_ARTIFACT_SUPERVISOR_BINARY="$BIN/whoathere-artifact-supervisor" \
  WHOATHERE_ARTIFACT_SUPERVISOR_KEYGEN_BINARY="$BIN/whoathere-artifact-supervisor-keygen" \
  "$PROVISIONER" --preflight "$STATE")
printf '%s\n' "$OUTPUT" | grep -q '^artifact_supervisor_preflight=true$'
printf '%s\n' "$OUTPUT" | grep -q '^artifact_vsock_port=47079$'
printf '%s\n' "$OUTPUT" | grep -q '^package_username=_whoatherepkg$'
printf '%s\n' "$OUTPUT" | grep -q '^package_execution_enabled=false$'
printf '%s\n' "$OUTPUT" | grep -q '^sync_back_enabled=false$'

printf '%s\n' "$$" > "$STATE/bundle/runtime.pid"
set +e
OUTPUT=$(WHOATHERE_ARTIFACT_SUPERVISOR_BINARY="$BIN/whoathere-artifact-supervisor" \
  WHOATHERE_ARTIFACT_SUPERVISOR_KEYGEN_BINARY="$BIN/whoathere-artifact-supervisor-keygen" \
  "$PROVISIONER" --preflight "$STATE" 2>&1)
STATUS=$?
set -e
[ "$STATUS" -eq 20 ]
printf '%s\n' "$OUTPUT" | grep -q '^reason_code=artifact_supervisor_vm_must_be_stopped$'

echo "artifact_supervisor_provisioning_selftest=passed"
