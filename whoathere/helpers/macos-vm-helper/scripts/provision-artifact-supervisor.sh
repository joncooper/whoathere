#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WHOATHERE_ROOT=$(CDPATH= cd -- "$HELPER_ROOT/../.." && pwd)

usage() {
  echo "usage: $0 [--preflight] /absolute/path/to/macos-vm-state" >&2
  exit 64
}

PREFLIGHT=0
if [ "${1:-}" = "--preflight" ]; then
  PREFLIGHT=1
  shift
fi
[ "$#" -eq 1 ] || usage
STATE_DIR=$1
case "$STATE_DIR" in
  /*) ;;
  *) usage ;;
esac

BUNDLE_DIR="$STATE_DIR/bundle"
DISK_IMAGE="$BUNDLE_DIR/disk.img"
RUNTIME_PID="$BUNDLE_DIR/runtime.pid"
PUBLIC_KEY_DEST="$BUNDLE_DIR/artifact-supervisor-public-key.bin"
RECEIPT_DEST="$BUNDLE_DIR/artifact-supervisor-provisioning.json"
SUPERVISOR_BINARY=${WHOATHERE_ARTIFACT_SUPERVISOR_BINARY:-"$WHOATHERE_ROOT/target/release/whoathere-artifact-supervisor"}
KEYGEN_BINARY=${WHOATHERE_ARTIFACT_SUPERVISOR_KEYGEN_BINARY:-"$WHOATHERE_ROOT/target/release/whoathere-artifact-supervisor-keygen"}
PACKAGE_UID=${WHOATHERE_ARTIFACT_PACKAGE_UID:-502}
PACKAGE_GID=${WHOATHERE_ARTIFACT_PACKAGE_GID:-502}
CPU_COUNT=${WHOATHERE_ARTIFACT_CPU_COUNT:-2}
MEMORY_MIB=${WHOATHERE_ARTIFACT_MEMORY_MIB:-6144}
NODE_VERSION=${WHOATHERE_ARTIFACT_NODE_VERSION:-22.17.0}
NPM_VERSION=${WHOATHERE_ARTIFACT_NPM_VERSION:-11.18.0}

for value in "$PACKAGE_UID" "$PACKAGE_GID" "$CPU_COUNT" "$MEMORY_MIB"; do
  case "$value" in
    ''|0|*[!0-9]*)
      echo "artifact_supervisor_package_identity_invalid=true" >&2
      exit 64
      ;;
  esac
done
case "$NODE_VERSION:$NPM_VERSION" in
  *[!0-9A-Za-z._:+-]*|:|*:)
    echo "artifact_supervisor_runtime_version_invalid=true" >&2
    exit 64
    ;;
esac

BUILD_DIR=""
ATTACHED_DISK=""
cleanup() {
  if [ -n "$ATTACHED_DISK" ]; then
    hdiutil detach "$ATTACHED_DISK" >/dev/null 2>&1 || true
  fi
  if [ -n "$BUILD_DIR" ]; then
    rm -rf "$BUILD_DIR"
  fi
}
trap cleanup EXIT HUP INT TERM

preflight_reason=""
if [ ! -d "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
  preflight_reason="artifact_supervisor_state_directory_missing_or_unsafe"
elif [ ! -d "$BUNDLE_DIR" ] || [ -L "$BUNDLE_DIR" ]; then
  preflight_reason="artifact_supervisor_bundle_directory_missing_or_unsafe"
elif [ ! -f "$DISK_IMAGE" ] || [ -L "$DISK_IMAGE" ]; then
  preflight_reason="artifact_supervisor_disk_missing_or_unsafe"
elif [ ! -x "$SUPERVISOR_BINARY" ] || [ -L "$SUPERVISOR_BINARY" ]; then
  preflight_reason="artifact_supervisor_release_binary_missing"
elif [ ! -x "$KEYGEN_BINARY" ] || [ -L "$KEYGEN_BINARY" ]; then
  preflight_reason="artifact_supervisor_keygen_binary_missing"
elif [ -f "$RUNTIME_PID" ]; then
  RUNTIME_VALUE=$(cat "$RUNTIME_PID" 2>/dev/null || true)
  case "$RUNTIME_VALUE" in
    ''|*[!0-9]*)
      preflight_reason="artifact_supervisor_runtime_state_invalid"
      ;;
    *)
      if kill -0 "$RUNTIME_VALUE" 2>/dev/null; then
        preflight_reason="artifact_supervisor_vm_must_be_stopped"
      fi
      ;;
  esac
fi

if [ "$PREFLIGHT" -eq 1 ]; then
  if [ -n "$preflight_reason" ]; then
    echo "artifact_supervisor_preflight=false"
    echo "reason_code=$preflight_reason"
    exit 20
  fi
  echo "artifact_supervisor_preflight=true"
  echo "package_uid=$PACKAGE_UID"
  echo "package_gid=$PACKAGE_GID"
  echo "artifact_vsock_port=47079"
  echo "package_execution_enabled=false"
  echo "sync_back_enabled=false"
  exit 0
fi

if [ -n "$preflight_reason" ]; then
  echo "reason_code=$preflight_reason" >&2
  exit 20
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "reason_code=artifact_supervisor_provisioning_requires_root" >&2
  exit 64
fi

STATE_UID=$(stat -f '%u' "$STATE_DIR")
STATE_GID=$(stat -f '%g' "$STATE_DIR")
if [ -n "${SUDO_UID:-}" ] && [ "$STATE_UID" -ne "$SUDO_UID" ]; then
  echo "reason_code=artifact_supervisor_state_owner_mismatch" >&2
  exit 64
fi

BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-artifact-supervisor.XXXXXX")
chmod 0700 "$BUILD_DIR"
KEY_DIR="$BUILD_DIR/keys"
install -d -o root -g wheel -m 0700 "$KEY_DIR"
"$KEYGEN_BINARY" "$KEY_DIR"

SEED_FILE="$KEY_DIR/artifact-supervisor-ed25519.seed"
PUBLIC_KEY_FILE="$KEY_DIR/artifact-supervisor-public-key.bin"
[ "$(stat -f '%z' "$SEED_FILE")" -eq 32 ] || exit 70
[ "$(stat -f '%z' "$PUBLIC_KEY_FILE")" -eq 32 ] || exit 70

SUPERVISOR_STAGED="$BUILD_DIR/whoathere-artifact-supervisor"
install -o root -g wheel -m 0755 "$SUPERVISOR_BINARY" "$SUPERVISOR_STAGED"
/usr/bin/codesign --force --sign - "$SUPERVISOR_STAGED" >/dev/null
/usr/bin/codesign --verify --strict "$SUPERVISOR_STAGED" >/dev/null

CONFIG_FILE="$BUILD_DIR/artifact-supervisor.json"
printf '%s' "{\"package_gid\":\"$PACKAGE_GID\",\"package_uid\":\"$PACKAGE_UID\",\"schema_version\":\"whoathere.artifact_guest_supervisor_config.v1\"}" > "$CONFIG_FILE"
chmod 0400 "$CONFIG_FILE"

SUPERVISOR_DIGEST=$(shasum -a 256 "$SUPERVISOR_STAGED" | awk '{print $1}')
CONFIG_DIGEST=$(shasum -a 256 "$CONFIG_FILE" | awk '{print $1}')
PUBLIC_KEY_DIGEST=$(shasum -a 256 "$PUBLIC_KEY_FILE" | awk '{print $1}')
BASE_GENERATION_ID="artifact-${PUBLIC_KEY_DIGEST%${PUBLIC_KEY_DIGEST#????????????????}}"
CLONE_IMPLEMENTATION_DIGEST=$(printf '%s' 'whoathere.swift.fclonefileat.direct.v1' | shasum -a 256 | awk '{print $1}')

PLIST_FILE="$BUILD_DIR/com.whoathere.artifact-supervisor.plist"
cat > "$PLIST_FILE" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.whoathere.artifact-supervisor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/libexec/whoathere-artifact-supervisor</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>/var/log/whoathere-artifact-supervisor.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/whoathere-artifact-supervisor.err.log</string>
</dict>
</plist>
EOF
plutil -lint "$PLIST_FILE" >/dev/null

ATTACH_OUTPUT=$(hdiutil attach -readwrite -owners on "$DISK_IMAGE")
printf '%s\n' "$ATTACH_OUTPUT"
ATTACHED_DISK=$(printf '%s\n' "$ATTACH_OUTPUT" | awk '/GUID_partition_scheme/ { print $1; exit }')
DATA_MOUNT=$(printf '%s\n' "$ATTACH_OUTPUT" | awk -F '\t' '$NF ~ /^\/Volumes\/Data/ { print $NF; exit }')
if [ -z "$ATTACHED_DISK" ] || [ -z "$DATA_MOUNT" ] || [ ! -d "$DATA_MOUNT/Library/LaunchDaemons" ]; then
  echo "reason_code=artifact_supervisor_guest_data_volume_missing" >&2
  exit 70
fi

NODE_EXECUTABLE="$DATA_MOUNT/usr/local/whoathere/node/bin/node"
NPM_CLI="$DATA_MOUNT/usr/local/whoathere/node/lib/node_modules/npm/bin/npm-cli.js"
if [ ! -x "$NODE_EXECUTABLE" ] || [ -L "$NODE_EXECUTABLE" ] || [ ! -f "$NPM_CLI" ] || [ -L "$NPM_CLI" ]; then
  echo "reason_code=artifact_supervisor_measured_node_npm_missing" >&2
  exit 70
fi
NODE_EXECUTABLE_DIGEST=$(shasum -a 256 "$NODE_EXECUTABLE" | awk '{print $1}')
NPM_CLI_DIGEST=$(shasum -a 256 "$NPM_CLI" | awk '{print $1}')

for path in \
  "$DATA_MOUNT/usr/local/libexec" \
  "$DATA_MOUNT/Library/Application Support/WhoaThere" \
  "$DATA_MOUNT/var/db/whoathere" \
  "$DATA_MOUNT/var/db/whoathere/artifact-staging" \
  "$DATA_MOUNT/usr/local/libexec/whoathere-artifact-supervisor" \
  "$DATA_MOUNT/Library/Application Support/WhoaThere/artifact-supervisor.json" \
  "$DATA_MOUNT/Library/Application Support/WhoaThere/artifact-supervisor-ed25519.seed" \
  "$DATA_MOUNT/Library/LaunchDaemons/com.whoathere.artifact-supervisor.plist"; do
  if [ -L "$path" ]; then
    echo "reason_code=artifact_supervisor_guest_destination_symlink_rejected" >&2
    exit 70
  fi
done

install -d -o root -g wheel -m 0755 "$DATA_MOUNT/usr/local/libexec"
install -o root -g wheel -m 0755 "$SUPERVISOR_STAGED" "$DATA_MOUNT/usr/local/libexec/whoathere-artifact-supervisor"
install -d -o root -g wheel -m 0700 "$DATA_MOUNT/Library/Application Support/WhoaThere"
install -o root -g wheel -m 0400 "$CONFIG_FILE" "$DATA_MOUNT/Library/Application Support/WhoaThere/artifact-supervisor.json"
install -o root -g wheel -m 0400 "$SEED_FILE" "$DATA_MOUNT/Library/Application Support/WhoaThere/artifact-supervisor-ed25519.seed"
install -d -o root -g wheel -m 0700 "$DATA_MOUNT/var/db/whoathere"
install -d -o root -g wheel -m 0700 "$DATA_MOUNT/var/db/whoathere/artifact-staging"
install -o root -g wheel -m 0644 "$PLIST_FILE" "$DATA_MOUNT/Library/LaunchDaemons/com.whoathere.artifact-supervisor.plist"
xattr -d com.apple.quarantine "$DATA_MOUNT/usr/local/libexec/whoathere-artifact-supervisor" >/dev/null 2>&1 || true
sync
hdiutil detach "$ATTACHED_DISK" >/dev/null
ATTACHED_DISK=""

RECEIPT_FILE="$BUILD_DIR/artifact-supervisor-provisioning.json"
printf '%s' "{\"artifact_vsock_port\":\"47079\",\"base_generation_id\":\"$BASE_GENERATION_ID\",\"clone_implementation_sha256\":\"sha256:$CLONE_IMPLEMENTATION_DIGEST\",\"cpu_count\":\"$CPU_COUNT\",\"guest_auth_public_key_sha256\":\"sha256:$PUBLIC_KEY_DIGEST\",\"guest_supervisor_sha256\":\"sha256:$SUPERVISOR_DIGEST\",\"memory_mib\":\"$MEMORY_MIB\",\"node_executable_sha256\":\"sha256:$NODE_EXECUTABLE_DIGEST\",\"node_version\":\"$NODE_VERSION\",\"npm_cli_sha256\":\"sha256:$NPM_CLI_DIGEST\",\"npm_version\":\"$NPM_VERSION\",\"package_execution_enabled\":false,\"package_gid\":\"$PACKAGE_GID\",\"package_uid\":\"$PACKAGE_UID\",\"runner_configuration_sha256\":\"sha256:$CONFIG_DIGEST\",\"schema_version\":\"whoathere.artifact_supervisor_provisioning.v1\",\"sync_back_enabled\":false}" > "$RECEIPT_FILE"
chmod 0400 "$RECEIPT_FILE"

PUBLIC_TMP="$BUNDLE_DIR/.artifact-supervisor-public-key.bin.$$"
RECEIPT_TMP="$BUNDLE_DIR/.artifact-supervisor-provisioning.json.$$"
install -o "$STATE_UID" -g "$STATE_GID" -m 0400 "$PUBLIC_KEY_FILE" "$PUBLIC_TMP"
install -o "$STATE_UID" -g "$STATE_GID" -m 0400 "$RECEIPT_FILE" "$RECEIPT_TMP"
mv -f "$PUBLIC_TMP" "$PUBLIC_KEY_DEST"
mv -f "$RECEIPT_TMP" "$RECEIPT_DEST"

echo "artifact_supervisor_provisioned=true"
echo "base_generation_id=$BASE_GENERATION_ID"
echo "guest_supervisor_sha256=sha256:$SUPERVISOR_DIGEST"
echo "guest_auth_public_key_sha256=sha256:$PUBLIC_KEY_DIGEST"
echo "runner_configuration_sha256=sha256:$CONFIG_DIGEST"
echo "node_executable_sha256=sha256:$NODE_EXECUTABLE_DIGEST"
echo "node_version=$NODE_VERSION"
echo "npm_cli_sha256=sha256:$NPM_CLI_DIGEST"
echo "npm_version=$NPM_VERSION"
echo "package_uid=$PACKAGE_UID"
echo "package_gid=$PACKAGE_GID"
echo "cpu_count=$CPU_COUNT"
echo "memory_mib=$MEMORY_MIB"
echo "artifact_vsock_port=47079"
echo "package_execution_enabled=false"
echo "sync_back_enabled=false"
