#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

state_dir_default() {
  if [ -n "${WHOATHERE_VM_STATE_DIR:-}" ]; then
    printf '%s\n' "$WHOATHERE_VM_STATE_DIR"
    return
  fi

  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    USER_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    if [ -n "$USER_HOME" ]; then
      printf '%s\n' "$USER_HOME/.whoathere/macos-vm-validation"
      return
    fi
  fi

  printf '%s\n' "$HOME/.whoathere/macos-vm-validation"
}

STATE_DIR=${1:-$(state_dir_default)}
BUNDLE_DIR="$STATE_DIR/bundle"
DISK_IMAGE="$BUNDLE_DIR/disk.img"
RUNTIME_PID="$BUNDLE_DIR/runtime.pid"
AGENT_SOURCE="$HELPER_ROOT/guest-agent/whoathere-guest-ready.c"
RECEIPT_PATH="$BUNDLE_DIR/guest-provisioning.json"
BUILD_DIR=${TMPDIR:-/tmp}/whoathere-guest-ready.$$
AGENT_BINARY="$BUILD_DIR/whoathere-guest-ready"
ATTACHED_DISK=""

cleanup() {
  if [ -n "$ATTACHED_DISK" ]; then
    hdiutil detach "$ATTACHED_DISK" >/dev/null 2>&1 || true
  fi
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT HUP INT TERM

if [ "$(id -u)" -ne 0 ]; then
  echo "admin_required=true" >&2
  echo "reason_code=guest_readiness_provisioning_requires_root_owned_launchdaemon" >&2
  echo "rerun=sudo $0 $STATE_DIR" >&2
  exit 64
fi

if [ ! -f "$DISK_IMAGE" ]; then
  echo "disk_image_not_found=$DISK_IMAGE" >&2
  exit 64
fi

if [ ! -f "$AGENT_SOURCE" ]; then
  echo "guest_agent_source_not_found=$AGENT_SOURCE" >&2
  exit 64
fi

if [ -f "$RUNTIME_PID" ]; then
  PID=$(cat "$RUNTIME_PID" 2>/dev/null || true)
  case "$PID" in
    ''|*[!0-9]*)
      ;;
    *)
      if kill -0 "$PID" 2>/dev/null; then
        echo "vm_runtime_running=true" >&2
        echo "stop_vm_first=$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper suspend --state-dir $STATE_DIR --execute --json" >&2
        exit 20
      fi
      ;;
  esac
fi

mkdir -p "$BUILD_DIR"
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -o "$AGENT_BINARY" "$AGENT_SOURCE"
/usr/bin/codesign --force --sign - "$AGENT_BINARY" >/dev/null 2>&1 || true
AGENT_DIGEST=$(shasum -a 256 "$AGENT_BINARY" | awk '{print $1}')

ATTACH_OUTPUT=$(hdiutil attach -readwrite -owners on "$DISK_IMAGE")
printf '%s\n' "$ATTACH_OUTPUT"
ATTACHED_DISK=$(printf '%s\n' "$ATTACH_OUTPUT" | awk '/GUID_partition_scheme/ { print $1; exit }')
DATA_MOUNT=$(printf '%s\n' "$ATTACH_OUTPUT" | awk -F '\t' '$NF ~ /^\/Volumes\/Data/ { print $NF; exit }')

if [ -z "$ATTACHED_DISK" ]; then
  echo "attached_disk_not_found=true" >&2
  exit 70
fi

if [ -z "$DATA_MOUNT" ] || [ ! -d "$DATA_MOUNT/Library/LaunchDaemons" ]; then
  echo "guest_data_volume_mount_not_found=true" >&2
  exit 70
fi

install -d -o root -g wheel -m 0755 "$DATA_MOUNT/usr/local/whoathere"
install -o root -g wheel -m 0755 "$AGENT_BINARY" "$DATA_MOUNT/usr/local/whoathere/whoathere-guest-ready"

PLIST_TMP="$BUILD_DIR/com.whoathere.guest-ready.plist"
cat > "$PLIST_TMP" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.whoathere.guest-ready</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/whoathere/whoathere-guest-ready</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>/var/log/whoathere-guest-ready.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/whoathere-guest-ready.err.log</string>
</dict>
</plist>
EOF

plutil -lint "$PLIST_TMP" >/dev/null
install -o root -g wheel -m 0644 "$PLIST_TMP" "$DATA_MOUNT/Library/LaunchDaemons/com.whoathere.guest-ready.plist"
xattr -d com.apple.quarantine "$DATA_MOUNT/usr/local/whoathere/whoathere-guest-ready" >/dev/null 2>&1 || true

cat > "$RECEIPT_PATH" <<EOF
{
  "schema_version": "whoathere.macos_vm.guest_provisioning.v1",
  "method": "offline_root_owned_launchdaemon",
  "agent_path": "/usr/local/whoathere/whoathere-guest-ready",
  "launchdaemon_path": "/Library/LaunchDaemons/com.whoathere.guest-ready.plist",
  "agent_sha256": "sha256:$AGENT_DIGEST",
  "high_risk_package_execution_enabled": false,
  "host_home_mounted": false,
  "host_secrets_mounted": false
}
EOF
chmod 0644 "$RECEIPT_PATH"

echo "guest_readiness_provisioned=true"
echo "state_dir=$STATE_DIR"
echo "agent_sha256=sha256:$AGENT_DIGEST"
echo "next_start=$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper start --state-dir $STATE_DIR --execute --json"
