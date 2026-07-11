#!/bin/sh
set -eu

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-sdist-provision-selftest.XXXXXX")
cleanup() {
  case "$ROOT" in
    "${TMPDIR:-/tmp}"/whoathere-sdist-provision-selftest.*) rm -rf "$ROOT" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

STATE="$ROOT/state"
BIN="$ROOT/bin"
mkdir -p "$STATE/bundle" "$BIN"
chmod 0700 "$STATE" "$BIN"
: > "$STATE/bundle/disk.img"
for name in whoathere-sdist-supervisor whoathere-sdist-supervisor-keygen; do
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$BIN/$name"
  chmod 0700 "$BIN/$name"
done

PROVISIONER="$(CDPATH= cd -- "$(dirname -- "$0")/../whoathere/helpers/macos-vm-helper/scripts" && pwd)/provision-sdist-supervisor.sh"
RECEIPT_LIB="$(dirname -- "$PROVISIONER")/sdist-supervisor-receipt-lib.sh"
OUTPUT=$(WHOATHERE_SDIST_SUPERVISOR_BINARY="$BIN/whoathere-sdist-supervisor" \
  WHOATHERE_SDIST_SUPERVISOR_KEYGEN_BINARY="$BIN/whoathere-sdist-supervisor-keygen" \
  "$PROVISIONER" --preflight "$STATE")
printf '%s\n' "$OUTPUT" | grep -q '^sdist_supervisor_preflight=true$'
printf '%s\n' "$OUTPUT" | grep -q '^sdist_vsock_port=47081$'
printf '%s\n' "$OUTPUT" | grep -q '^package_username=_whoatherepkg$'
printf '%s\n' "$OUTPUT" | grep -q '^package_execution_enabled=false$'
printf '%s\n' "$OUTPUT" | grep -q '^sync_back_enabled=false$'
printf '%s\n' "$OUTPUT" | grep -q '^build_closure_materialization_enabled=false$'
printf '%s\n' "$OUTPUT" | grep -q '^public_resolution_enabled=false$'

. "$RECEIPT_LIB"
DIGEST=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
RECEIPT=$(whoathere_render_sdist_supervisor_receipt \
  sdist-base-test "$DIGEST" 2 "$DIGEST" "$DIGEST" "$DIGEST" 6144 \
  499 499 _whoatherepkg "$DIGEST" 26.1.2 "$DIGEST" 3.12.13 "$DIGEST")
EXPECTED="{\"base_generation_id\":\"sdist-base-test\",\"build_closure_materialization_enabled\":false,\"clone_implementation_sha256\":\"$DIGEST\",\"cpu_count\":\"2\",\"guest_auth_public_key_sha256\":\"$DIGEST\",\"guest_protocol_sha256\":\"$DIGEST\",\"guest_supervisor_sha256\":\"$DIGEST\",\"memory_mib\":\"6144\",\"package_execution_enabled\":false,\"package_gid\":\"499\",\"package_uid\":\"499\",\"package_username\":\"_whoatherepkg\",\"pip_cli_sha256\":\"$DIGEST\",\"pip_version\":\"26.1.2\",\"public_resolution_enabled\":false,\"python_executable_sha256\":\"$DIGEST\",\"python_version\":\"3.12.13\",\"runner_configuration_sha256\":\"$DIGEST\",\"schema_version\":\"whoathere.sdist_supervisor_provisioning.v1\",\"sdist_vsock_port\":\"47081\",\"sync_back_enabled\":false}"
[ "$RECEIPT" = "$EXPECTED" ]

chmod 0777 "$STATE/bundle"
set +e
OUTPUT=$(WHOATHERE_SDIST_SUPERVISOR_BINARY="$BIN/whoathere-sdist-supervisor" \
  WHOATHERE_SDIST_SUPERVISOR_KEYGEN_BINARY="$BIN/whoathere-sdist-supervisor-keygen" \
  "$PROVISIONER" --preflight "$STATE" 2>&1)
STATUS=$?
set -e
[ "$STATUS" -eq 20 ]
printf '%s\n' "$OUTPUT" \
  | grep -q '^reason_code=sdist_supervisor_bundle_directory_owner_or_mode_unsafe$'
chmod 0755 "$STATE/bundle"

printf '%s\n' "$$" > "$STATE/bundle/runtime.pid"
set +e
OUTPUT=$(WHOATHERE_SDIST_SUPERVISOR_BINARY="$BIN/whoathere-sdist-supervisor" \
  WHOATHERE_SDIST_SUPERVISOR_KEYGEN_BINARY="$BIN/whoathere-sdist-supervisor-keygen" \
  "$PROVISIONER" --preflight "$STATE" 2>&1)
STATUS=$?
set -e
[ "$STATUS" -eq 20 ]
printf '%s\n' "$OUTPUT" | grep -q '^reason_code=sdist_supervisor_vm_must_be_stopped$'

echo "sdist_supervisor_provisioning_selftest=passed"
