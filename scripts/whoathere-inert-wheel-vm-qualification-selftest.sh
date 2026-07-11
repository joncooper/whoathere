#!/bin/sh
set -eu

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-wheel-vm-qualification.XXXXXX")
cleanup() {
  case "$ROOT" in
    "${TMPDIR:-/tmp}"/whoathere-wheel-vm-qualification.*) rm -rf "$ROOT" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
QUALIFIER="$REPO_ROOT/scripts/whoathere-inert-wheel-vm-qualification.sh"
STATE="$ROOT/state"
BUNDLE="$STATE/bundle"
BIN="$ROOT/bin"
mkdir -p "$BUNDLE" "$BIN"
chmod 0700 "$STATE" "$BUNDLE" "$BIN"
for name in disk.img auxiliary-storage hardware-model.bin machine-identifier.bin \
  wheel-supervisor-public-key.bin wheel-supervisor-provisioning.json; do
  printf '%s' "inert-$name" > "$BUNDLE/$name"
  chmod 0600 "$BUNDLE/$name"
done
for name in helper generator; do
  printf '%s\n' '#!/bin/sh' 'exit 0' > "$BIN/$name"
  chmod 0700 "$BIN/$name"
done

OUTPUT=$(
  WHOATHERE_MACOS_VM_HELPER_BINARY="$BIN/helper" \
  WHOATHERE_MEASURED_WHEEL_GENERATOR_BINARY="$BIN/generator" \
  "$QUALIFIER" --preflight "$STATE"
)
printf '%s\n' "$OUTPUT" | grep -q '^wheel_vm_qualification_preflight=true$'
printf '%s\n' "$OUTPUT" | grep -q '^network_device_count=0$'
printf '%s\n' "$OUTPUT" | grep -q '^package_execution_enabled=false$'
printf '%s\n' "$OUTPUT" | grep -q '^sync_back_enabled=false$'

printf '%s\n' "$$" > "$BUNDLE/runtime.pid"
chmod 0600 "$BUNDLE/runtime.pid"
set +e
OUTPUT=$(
  WHOATHERE_MACOS_VM_HELPER_BINARY="$BIN/helper" \
  WHOATHERE_MEASURED_WHEEL_GENERATOR_BINARY="$BIN/generator" \
  "$QUALIFIER" --preflight "$STATE" 2>&1
)
STATUS=$?
set -e
[ "$STATUS" -eq 20 ]
printf '%s\n' "$OUTPUT" | grep -q '^reason_code=wheel_vm_qualification_vm_must_be_stopped$'

echo "inert_wheel_vm_qualification_selftest=passed"
