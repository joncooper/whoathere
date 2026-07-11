#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HELPER_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
WHOATHERE_ROOT=$(CDPATH= cd -- "$HELPER_ROOT/../.." && pwd)
. "$SCRIPT_DIR/artifact-package-account-lib.sh"
. "$SCRIPT_DIR/sdist-supervisor-receipt-lib.sh"

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
PUBLIC_KEY_DEST="$BUNDLE_DIR/sdist-supervisor-public-key.bin"
RECEIPT_DEST="$BUNDLE_DIR/sdist-supervisor-provisioning.json"
SUPERVISOR_BINARY=${WHOATHERE_SDIST_SUPERVISOR_BINARY:-"$WHOATHERE_ROOT/target/release/whoathere-sdist-supervisor"}
KEYGEN_BINARY=${WHOATHERE_SDIST_SUPERVISOR_KEYGEN_BINARY:-"$WHOATHERE_ROOT/target/release/whoathere-sdist-supervisor-keygen"}
PACKAGE_USERNAME=_whoatherepkg
PACKAGE_UID=${WHOATHERE_SDIST_PACKAGE_UID:-499}
PACKAGE_GID=${WHOATHERE_SDIST_PACKAGE_GID:-499}
CPU_COUNT=${WHOATHERE_SDIST_CPU_COUNT:-2}
MEMORY_MIB=${WHOATHERE_SDIST_MEMORY_MIB:-6144}
EXPECTED_PYTHON_VERSION=${WHOATHERE_SDIST_EXPECTED_PYTHON_VERSION:-}
EXPECTED_PIP_VERSION=${WHOATHERE_SDIST_EXPECTED_PIP_VERSION:-}

for value in "$PACKAGE_UID" "$PACKAGE_GID" "$CPU_COUNT" "$MEMORY_MIB"; do
  case "$value" in
    ''|0|*[!0-9]*)
      echo "sdist_supervisor_package_identity_invalid=true" >&2
      exit 64
      ;;
  esac
done
case "$PACKAGE_UID:$PACKAGE_GID" in
  0[0-9]*:*|*:0[0-9]*)
    echo "sdist_supervisor_package_identity_invalid=true" >&2
    exit 64
    ;;
esac
case "$EXPECTED_PYTHON_VERSION:$EXPECTED_PIP_VERSION" in
  *[!0-9A-Za-z._:+-]*)
    echo "sdist_supervisor_runtime_version_invalid=true" >&2
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

EXPECTED_OWNER_UID=${SUDO_UID:-$(id -u)}
preflight_reason=""
if [ ! -d "$STATE_DIR" ] || [ -L "$STATE_DIR" ]; then
  preflight_reason="sdist_supervisor_state_directory_missing_or_unsafe"
elif [ ! -d "$BUNDLE_DIR" ] || [ -L "$BUNDLE_DIR" ]; then
  preflight_reason="sdist_supervisor_bundle_directory_missing_or_unsafe"
elif [ ! -f "$DISK_IMAGE" ] || [ -L "$DISK_IMAGE" ]; then
  preflight_reason="sdist_supervisor_disk_missing_or_unsafe"
elif [ ! -x "$SUPERVISOR_BINARY" ] || [ -L "$SUPERVISOR_BINARY" ]; then
  preflight_reason="sdist_supervisor_release_binary_missing"
elif [ ! -x "$KEYGEN_BINARY" ] || [ -L "$KEYGEN_BINARY" ]; then
  preflight_reason="sdist_supervisor_keygen_binary_missing"
elif [ "$(stat -f '%u' "$STATE_DIR")" -ne "$EXPECTED_OWNER_UID" ] \
  || [ $((0$(stat -f '%Lp' "$STATE_DIR") & 0022)) -ne 0 ]; then
  preflight_reason="sdist_supervisor_state_directory_owner_or_mode_unsafe"
elif [ "$(stat -f '%u' "$BUNDLE_DIR")" -ne "$EXPECTED_OWNER_UID" ] \
  || [ $((0$(stat -f '%Lp' "$BUNDLE_DIR") & 0022)) -ne 0 ]; then
  preflight_reason="sdist_supervisor_bundle_directory_owner_or_mode_unsafe"
elif [ "$(stat -f '%u' "$DISK_IMAGE")" -ne "$EXPECTED_OWNER_UID" ] \
  || [ "$(stat -f '%l' "$DISK_IMAGE")" -ne 1 ] \
  || [ $((0$(stat -f '%Lp' "$DISK_IMAGE") & 0022)) -ne 0 ]; then
  preflight_reason="sdist_supervisor_disk_owner_or_mode_unsafe"
elif [ "$(stat -f '%u' "$SUPERVISOR_BINARY")" -ne "$EXPECTED_OWNER_UID" ] \
  || [ "$(stat -f '%l' "$SUPERVISOR_BINARY")" -ne 1 ] \
  || [ $((0$(stat -f '%Lp' "$SUPERVISOR_BINARY") & 0022)) -ne 0 ]; then
  preflight_reason="sdist_supervisor_release_binary_owner_or_mode_unsafe"
elif [ "$(stat -f '%u' "$KEYGEN_BINARY")" -ne "$EXPECTED_OWNER_UID" ] \
  || [ "$(stat -f '%l' "$KEYGEN_BINARY")" -ne 1 ] \
  || [ $((0$(stat -f '%Lp' "$KEYGEN_BINARY") & 0022)) -ne 0 ]; then
  preflight_reason="sdist_supervisor_keygen_binary_owner_or_mode_unsafe"
elif [ -f "$RUNTIME_PID" ]; then
  RUNTIME_VALUE=$(cat "$RUNTIME_PID" 2>/dev/null || true)
  case "$RUNTIME_VALUE" in
    ''|*[!0-9]*)
      preflight_reason="sdist_supervisor_runtime_state_invalid"
      ;;
    *)
      if kill -0 "$RUNTIME_VALUE" 2>/dev/null; then
        preflight_reason="sdist_supervisor_vm_must_be_stopped"
      fi
      ;;
  esac
fi

if [ "$PREFLIGHT" -eq 1 ]; then
  if [ -n "$preflight_reason" ]; then
    echo "sdist_supervisor_preflight=false"
    echo "reason_code=$preflight_reason"
    exit 20
  fi
  echo "sdist_supervisor_preflight=true"
  echo "package_uid=$PACKAGE_UID"
  echo "package_gid=$PACKAGE_GID"
  echo "package_username=$PACKAGE_USERNAME"
  echo "sdist_vsock_port=47081"
  echo "package_execution_enabled=false"
  echo "sync_back_enabled=false"
  echo "build_closure_materialization_enabled=false"
  echo "public_resolution_enabled=false"
  exit 0
fi

if [ -n "$preflight_reason" ]; then
  echo "reason_code=$preflight_reason" >&2
  exit 20
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "reason_code=sdist_supervisor_provisioning_requires_root" >&2
  exit 64
fi

STATE_UID=$(stat -f '%u' "$STATE_DIR")
STATE_GID=$(stat -f '%g' "$STATE_DIR")
if [ -n "${SUDO_UID:-}" ] && [ "$STATE_UID" -ne "$SUDO_UID" ]; then
  echo "reason_code=sdist_supervisor_state_owner_mismatch" >&2
  exit 64
fi

BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-sdist-supervisor.XXXXXX")
chmod 0700 "$BUILD_DIR"
KEY_DIR="$BUILD_DIR/keys"
install -d -o root -g wheel -m 0700 "$KEY_DIR"
"$KEYGEN_BINARY" "$KEY_DIR"

SEED_FILE="$KEY_DIR/sdist-supervisor-ed25519.seed"
PUBLIC_KEY_FILE="$KEY_DIR/sdist-supervisor-public-key.bin"
[ "$(stat -f '%z' "$SEED_FILE")" -eq 32 ] || exit 70
[ "$(stat -f '%z' "$PUBLIC_KEY_FILE")" -eq 32 ] || exit 70

SUPERVISOR_STAGED="$BUILD_DIR/whoathere-sdist-supervisor"
install -o root -g wheel -m 0755 "$SUPERVISOR_BINARY" "$SUPERVISOR_STAGED"
/usr/bin/codesign --force --sign - "$SUPERVISOR_STAGED" >/dev/null
/usr/bin/codesign --verify --strict "$SUPERVISOR_STAGED" >/dev/null

CONFIG_FILE="$BUILD_DIR/sdist-supervisor.json"
printf '%s' "{\"package_gid\":\"$PACKAGE_GID\",\"package_uid\":\"$PACKAGE_UID\",\"package_username\":\"$PACKAGE_USERNAME\",\"schema_version\":\"whoathere.sdist_guest_supervisor_config.v1\"}" > "$CONFIG_FILE"
chmod 0400 "$CONFIG_FILE"

SUPERVISOR_DIGEST=$(shasum -a 256 "$SUPERVISOR_STAGED" | awk '{print $1}')
CONFIG_DIGEST=$(shasum -a 256 "$CONFIG_FILE" | awk '{print $1}')
PUBLIC_KEY_DIGEST=$(shasum -a 256 "$PUBLIC_KEY_FILE" | awk '{print $1}')
BASE_GENERATION_ID="sdist-${PUBLIC_KEY_DIGEST%${PUBLIC_KEY_DIGEST#????????????????}}"
CLONE_IMPLEMENTATION_DIGEST=$(printf '%s' 'whoathere.swift.fclonefileat.direct.v1' | shasum -a 256 | awk '{print $1}')
GUEST_PROTOCOL_DIGEST=$(printf '%s' 'whoathere.sdist_artifact_scenario.v1' | shasum -a 256 | awk '{print $1}')

PLIST_FILE="$BUILD_DIR/com.whoathere.sdist-supervisor.plist"
cat > "$PLIST_FILE" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.whoathere.sdist-supervisor</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/libexec/whoathere-sdist-supervisor</string>
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
  <string>/var/log/whoathere-sdist-supervisor.out.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/whoathere-sdist-supervisor.err.log</string>
</dict>
</plist>
EOF
plutil -lint "$PLIST_FILE" >/dev/null

ATTACH_OUTPUT=$(hdiutil attach -readwrite -owners on "$DISK_IMAGE")
printf '%s\n' "$ATTACH_OUTPUT"
ATTACHED_DISK=$(printf '%s\n' "$ATTACH_OUTPUT" | awk '/GUID_partition_scheme/ { print $1; exit }')
DATA_MOUNT=$(printf '%s\n' "$ATTACH_OUTPUT" | awk -F '\t' '$NF ~ /^\/Volumes\/Data/ { print $NF; exit }')
if [ -z "$ATTACHED_DISK" ] || [ -z "$DATA_MOUNT" ] || [ ! -d "$DATA_MOUNT/Library/LaunchDaemons" ]; then
  echo "reason_code=sdist_supervisor_guest_data_volume_missing" >&2
  exit 70
fi

PYTHON_RUNTIME_ROOT="$DATA_MOUNT/usr/local/whoathere/python"
PYTHON_EXECUTABLE_LIST="$BUILD_DIR/python-executables"
find "$PYTHON_RUNTIME_ROOT/bin" -maxdepth 1 -type f -perm -111 -print 2>/dev/null \
  | awk -F/ '$NF ~ /^python3\.[0-9]+$/ { print }' \
  | sort > "$PYTHON_EXECUTABLE_LIST"
if [ "$(wc -l < "$PYTHON_EXECUTABLE_LIST" | awk '{print $1}')" -ne 1 ]; then
  echo "reason_code=sdist_supervisor_measured_python_pip_missing" >&2
  exit 70
fi
PYTHON_EXECUTABLE=$(cat "$PYTHON_EXECUTABLE_LIST")

PIP_CLI_LIST="$BUILD_DIR/pip-cli-files"
PIP_METADATA_LIST="$BUILD_DIR/pip-metadata-files"
find "$PYTHON_RUNTIME_ROOT/lib" -path '*/site-packages/pip/__main__.py' -type f -print \
  2>/dev/null | sort > "$PIP_CLI_LIST"
find "$PYTHON_RUNTIME_ROOT/lib" -path '*/site-packages/pip-*.dist-info/METADATA' -type f -print \
  2>/dev/null | sort > "$PIP_METADATA_LIST"
if [ "$(wc -l < "$PIP_CLI_LIST" | awk '{print $1}')" -ne 1 ] \
  || [ "$(wc -l < "$PIP_METADATA_LIST" | awk '{print $1}')" -ne 1 ]; then
  echo "reason_code=sdist_supervisor_measured_python_pip_missing" >&2
  exit 70
fi
PIP_CLI=$(cat "$PIP_CLI_LIST")
PIP_METADATA=$(cat "$PIP_METADATA_LIST")
if [ -L "$PYTHON_EXECUTABLE" ] || [ -L "$PIP_CLI" ] || [ -L "$PIP_METADATA" ]; then
  echo "reason_code=sdist_supervisor_measured_python_pip_unsafe" >&2
  exit 70
fi
if ! PYTHON_VERSION=$(
  "$PYTHON_EXECUTABLE" -I -S -c \
    'import sys; print(".".join(str(value) for value in sys.version_info[:3]))'
); then
  echo "reason_code=sdist_supervisor_measured_python_version_unavailable" >&2
  exit 70
fi
if ! PIP_VERSION=$(awk -F ': ' \
  '$1 == "Version" { print $2; found += 1 } END { if (found != 1) exit 1 }' \
  "$PIP_METADATA"); then
  echo "reason_code=sdist_supervisor_measured_pip_version_unavailable" >&2
  exit 70
fi
case "$PYTHON_VERSION:$PIP_VERSION" in
  *[!0-9A-Za-z._:+-]*|:|*:)
    echo "reason_code=sdist_supervisor_measured_python_pip_version_invalid" >&2
    exit 70
    ;;
esac
if [ -n "$EXPECTED_PYTHON_VERSION" ] && [ "$PYTHON_VERSION" != "$EXPECTED_PYTHON_VERSION" ]; then
  echo "reason_code=sdist_supervisor_measured_python_version_mismatch" >&2
  exit 70
fi
if [ -n "$EXPECTED_PIP_VERSION" ] && [ "$PIP_VERSION" != "$EXPECTED_PIP_VERSION" ]; then
  echo "reason_code=sdist_supervisor_measured_pip_version_mismatch" >&2
  exit 70
fi
PYTHON_EXECUTABLE_DIGEST=$(shasum -a 256 "$PYTHON_EXECUTABLE" | awk '{print $1}')
PIP_CLI_DIGEST=$(shasum -a 256 "$PIP_CLI" | awk '{print $1}')
whoathere_provision_package_account "$DATA_MOUNT" "$PACKAGE_USERNAME" "$PACKAGE_UID" "$PACKAGE_GID" 0

for path in \
  "$DATA_MOUNT/usr/local/libexec" \
  "$DATA_MOUNT/Library/Application Support/WhoaThere" \
  "$DATA_MOUNT/var/db/whoathere" \
  "$DATA_MOUNT/var/db/whoathere/sdist-staging" \
  "$DATA_MOUNT/usr/local/libexec/whoathere-sdist-supervisor" \
  "$DATA_MOUNT/Library/Application Support/WhoaThere/sdist-supervisor.json" \
  "$DATA_MOUNT/Library/Application Support/WhoaThere/sdist-supervisor-ed25519.seed" \
  "$DATA_MOUNT/Library/LaunchDaemons/com.whoathere.sdist-supervisor.plist"; do
  if [ -L "$path" ]; then
    echo "reason_code=sdist_supervisor_guest_destination_symlink_rejected" >&2
    exit 70
  fi
done

install -d -o root -g wheel -m 0755 "$DATA_MOUNT/usr/local/libexec"
install -o root -g wheel -m 0755 "$SUPERVISOR_STAGED" "$DATA_MOUNT/usr/local/libexec/whoathere-sdist-supervisor"
install -d -o root -g wheel -m 0700 "$DATA_MOUNT/Library/Application Support/WhoaThere"
install -o root -g wheel -m 0400 "$CONFIG_FILE" "$DATA_MOUNT/Library/Application Support/WhoaThere/sdist-supervisor.json"
install -o root -g wheel -m 0400 "$SEED_FILE" "$DATA_MOUNT/Library/Application Support/WhoaThere/sdist-supervisor-ed25519.seed"
install -d -o root -g wheel -m 0700 "$DATA_MOUNT/var/db/whoathere"
install -d -o root -g wheel -m 0700 "$DATA_MOUNT/var/db/whoathere/sdist-staging"
install -o root -g wheel -m 0644 "$PLIST_FILE" "$DATA_MOUNT/Library/LaunchDaemons/com.whoathere.sdist-supervisor.plist"
xattr -d com.apple.quarantine "$DATA_MOUNT/usr/local/libexec/whoathere-sdist-supervisor" >/dev/null 2>&1 || true
sync
hdiutil detach "$ATTACHED_DISK" >/dev/null
ATTACHED_DISK=""

RECEIPT_FILE="$BUILD_DIR/sdist-supervisor-provisioning.json"
whoathere_render_sdist_supervisor_receipt \
  "$BASE_GENERATION_ID" \
  "sha256:$CLONE_IMPLEMENTATION_DIGEST" \
  "$CPU_COUNT" \
  "sha256:$PUBLIC_KEY_DIGEST" \
  "sha256:$GUEST_PROTOCOL_DIGEST" \
  "sha256:$SUPERVISOR_DIGEST" \
  "$MEMORY_MIB" \
  "$PACKAGE_GID" \
  "$PACKAGE_UID" \
  "$PACKAGE_USERNAME" \
  "sha256:$PIP_CLI_DIGEST" \
  "$PIP_VERSION" \
  "sha256:$PYTHON_EXECUTABLE_DIGEST" \
  "$PYTHON_VERSION" \
  "sha256:$CONFIG_DIGEST" > "$RECEIPT_FILE"
chmod 0400 "$RECEIPT_FILE"

PUBLIC_TMP="$BUNDLE_DIR/.sdist-supervisor-public-key.bin.$$"
RECEIPT_TMP="$BUNDLE_DIR/.sdist-supervisor-provisioning.json.$$"
install -o "$STATE_UID" -g "$STATE_GID" -m 0400 "$PUBLIC_KEY_FILE" "$PUBLIC_TMP"
install -o "$STATE_UID" -g "$STATE_GID" -m 0400 "$RECEIPT_FILE" "$RECEIPT_TMP"
mv -f "$PUBLIC_TMP" "$PUBLIC_KEY_DEST"
mv -f "$RECEIPT_TMP" "$RECEIPT_DEST"

echo "sdist_supervisor_provisioned=true"
echo "base_generation_id=$BASE_GENERATION_ID"
echo "guest_supervisor_sha256=sha256:$SUPERVISOR_DIGEST"
echo "guest_auth_public_key_sha256=sha256:$PUBLIC_KEY_DIGEST"
echo "runner_configuration_sha256=sha256:$CONFIG_DIGEST"
echo "guest_protocol_sha256=sha256:$GUEST_PROTOCOL_DIGEST"
echo "python_executable_sha256=sha256:$PYTHON_EXECUTABLE_DIGEST"
echo "python_version=$PYTHON_VERSION"
echo "pip_cli_sha256=sha256:$PIP_CLI_DIGEST"
echo "pip_version=$PIP_VERSION"
echo "package_uid=$PACKAGE_UID"
echo "package_gid=$PACKAGE_GID"
echo "package_username=$PACKAGE_USERNAME"
echo "cpu_count=$CPU_COUNT"
echo "memory_mib=$MEMORY_MIB"
echo "sdist_vsock_port=47081"
echo "package_execution_enabled=false"
echo "sync_back_enabled=false"
echo "build_closure_materialization_enabled=false"
echo "public_resolution_enabled=false"
