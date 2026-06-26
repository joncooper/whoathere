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

user_home_default() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    USER_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    if [ -n "$USER_HOME" ]; then
      printf '%s\n' "$USER_HOME"
      return
    fi
  fi

  printf '%s\n' "$HOME"
}

wheel_dir_has_required_python_wheels() {
  WHEEL_CHECK_DIR=$1
  [ -n "$(find "$WHEEL_CHECK_DIR" -maxdepth 1 -name 'pip-*.whl' -type f -print -quit 2>/dev/null)" ] \
    && [ -n "$(find "$WHEEL_CHECK_DIR" -maxdepth 1 -name 'setuptools-*.whl' -type f -print -quit 2>/dev/null)" ]
}

wheel_dir_has_wheel_package() {
  WHEEL_CHECK_DIR=$1
  [ -n "$(find "$WHEEL_CHECK_DIR" -maxdepth 1 -name 'wheel-*.whl' -type f -print -quit 2>/dev/null)" ]
}

detect_wheel_package_file() {
  if [ -n "${WHOATHERE_WHEEL_PACKAGE_FILE:-}" ] && [ -f "$WHOATHERE_WHEEL_PACKAGE_FILE" ]; then
    printf 'operator_supplied:%s\n' "$WHOATHERE_WHEEL_PACKAGE_FILE"
    return
  fi

  REPO_WHEEL_DIR="$HELPER_ROOT/guest-tooling/python-wheels"
  if [ -d "$REPO_WHEEL_DIR" ] && wheel_dir_has_wheel_package "$REPO_WHEEL_DIR"; then
    WHEEL_FILE=$(find "$REPO_WHEEL_DIR" -maxdepth 1 -name 'wheel-*.whl' -type f -print 2>/dev/null | sort | tail -n 1)
    printf 'repo_guest_tooling:%s\n' "$WHEEL_FILE"
    return
  fi

  SEARCH_USER_HOME=$(user_home_default)
  FOUND_WHEEL_FILE="$BUILD_DIR/python-wheel-package-file"
  : > "$FOUND_WHEEL_FILE"
  if [ -d "$SEARCH_USER_HOME/Library/Caches/pypoetry/artifacts" ]; then
    find "$SEARCH_USER_HOME/Library/Caches/pypoetry/artifacts" -name 'wheel-*.whl' -type f 2>/dev/null | sort | while IFS= read -r CANDIDATE_WHEEL_FILE; do
      if [ ! -s "$FOUND_WHEEL_FILE" ]; then
        printf 'host_pypoetry_artifact:%s\n' "$CANDIDATE_WHEEL_FILE" > "$FOUND_WHEEL_FILE"
      fi
    done
  fi
  if [ -s "$FOUND_WHEEL_FILE" ]; then
    cat "$FOUND_WHEEL_FILE"
    return
  fi

  if [ -d "$SEARCH_USER_HOME/.cache/codex-runtimes" ]; then
    find "$SEARCH_USER_HOME/.cache/codex-runtimes" -name 'wheel-*.whl' -type f 2>/dev/null | sort | while IFS= read -r CANDIDATE_WHEEL_FILE; do
      if [ ! -s "$FOUND_WHEEL_FILE" ]; then
        printf 'host_codex_runtime_cache:%s\n' "$CANDIDATE_WHEEL_FILE" > "$FOUND_WHEEL_FILE"
      fi
    done
  fi
  if [ -s "$FOUND_WHEEL_FILE" ]; then
    cat "$FOUND_WHEEL_FILE"
  fi
}

python_runtime_dir_is_usable() {
  PYTHON_RUNTIME_CHECK_DIR=$1
  [ -x "$PYTHON_RUNTIME_CHECK_DIR/bin/python3" ]
}

detect_python_runtime_dir() {
  if [ -n "${WHOATHERE_PYTHON_RUNTIME_DIR:-}" ] && python_runtime_dir_is_usable "$WHOATHERE_PYTHON_RUNTIME_DIR"; then
    printf 'operator_supplied:%s\n' "$WHOATHERE_PYTHON_RUNTIME_DIR"
    return
  fi

  REPO_RUNTIME_DIR="$HELPER_ROOT/guest-tooling/python-runtime"
  if [ -d "$REPO_RUNTIME_DIR" ] && python_runtime_dir_is_usable "$REPO_RUNTIME_DIR"; then
    printf 'repo_guest_tooling:%s\n' "$REPO_RUNTIME_DIR"
    return
  fi

  SEARCH_USER_HOME=$(user_home_default)
  for CANDIDATE_RUNTIME_DIR in \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.11.11-macos-aarch64-none" \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.12.11-macos-aarch64-none" \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.13.2-macos-aarch64-none" \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.10.20-macos-aarch64-none"; do
    if [ -d "$CANDIDATE_RUNTIME_DIR" ] && python_runtime_dir_is_usable "$CANDIDATE_RUNTIME_DIR"; then
      printf 'host_uv_python_runtime:%s\n' "$CANDIDATE_RUNTIME_DIR"
      return
    fi
  done
}

copy_python_runtime() {
  PYTHON_RUNTIME_STATUS="not_found"
  PYTHON_RUNTIME_SOURCE_KIND="none"
  PYTHON_RUNTIME_NAME=""
  PYTHON_RUNTIME_PYTHON_SHA256=""
  PYTHON_RUNTIME_FILE_COUNT="0"
  PYTHON_RUNTIME_SIZE_KIB="0"

  RUNTIME_SELECTION=$(detect_python_runtime_dir || true)
  if [ -z "$RUNTIME_SELECTION" ]; then
    return
  fi

  PYTHON_RUNTIME_SOURCE_KIND=${RUNTIME_SELECTION%%:*}
  PYTHON_RUNTIME_SOURCE_DIR=${RUNTIME_SELECTION#*:}
  PYTHON_RUNTIME_NAME=$(basename "$PYTHON_RUNTIME_SOURCE_DIR")
  GUEST_RUNTIME_DIR="$DATA_MOUNT/usr/local/whoathere/python"
  rm -rf "$GUEST_RUNTIME_DIR"
  install -d -o root -g wheel -m 0755 "$GUEST_RUNTIME_DIR"
  if command -v ditto >/dev/null 2>&1; then
    ditto --noqtn "$PYTHON_RUNTIME_SOURCE_DIR" "$GUEST_RUNTIME_DIR"
  else
    cp -R "$PYTHON_RUNTIME_SOURCE_DIR"/. "$GUEST_RUNTIME_DIR"/
  fi
  chown -hR root:wheel "$GUEST_RUNTIME_DIR"
  find "$GUEST_RUNTIME_DIR" -type d -exec chmod 0755 {} +
  find "$GUEST_RUNTIME_DIR" -type f -exec chmod go-w {} +
  PYTHON_RUNTIME_STATUS="installed"
  PYTHON_RUNTIME_PYTHON_SHA256=$(shasum -a 256 "$PYTHON_RUNTIME_SOURCE_DIR/bin/python3" | awk '{print $1}')
  PYTHON_RUNTIME_FILE_COUNT=$(find "$PYTHON_RUNTIME_SOURCE_DIR" -type f 2>/dev/null | wc -l | awk '{print $1}')
  PYTHON_RUNTIME_SIZE_KIB=$(du -sk "$PYTHON_RUNTIME_SOURCE_DIR" | awk '{print $1}')
}

detect_python_wheel_dir() {
  if [ -n "${WHOATHERE_PYTHON_WHEEL_DIR:-}" ] && wheel_dir_has_required_python_wheels "$WHOATHERE_PYTHON_WHEEL_DIR"; then
    printf 'operator_supplied:%s\n' "$WHOATHERE_PYTHON_WHEEL_DIR"
    return
  fi

  REPO_WHEEL_DIR="$HELPER_ROOT/guest-tooling/python-wheels"
  if [ -d "$REPO_WHEEL_DIR" ] && wheel_dir_has_required_python_wheels "$REPO_WHEEL_DIR"; then
    printf 'repo_guest_tooling:%s\n' "$REPO_WHEEL_DIR"
    return
  fi

  SEARCH_USER_HOME=$(user_home_default)
  FOUND_WHEEL_DIR="$BUILD_DIR/python-wheel-dir"
  : > "$FOUND_WHEEL_DIR"
  if [ -d "$SEARCH_USER_HOME/.local/share/uv/python" ]; then
    find "$SEARCH_USER_HOME/.local/share/uv/python" -path '*/ensurepip/_bundled' -type d 2>/dev/null | while IFS= read -r CANDIDATE_WHEEL_DIR; do
      if [ ! -s "$FOUND_WHEEL_DIR" ] && wheel_dir_has_required_python_wheels "$CANDIDATE_WHEEL_DIR"; then
        printf 'host_uv_ensurepip_bundle:%s\n' "$CANDIDATE_WHEEL_DIR" > "$FOUND_WHEEL_DIR"
      fi
    done
  fi
  if [ -s "$FOUND_WHEEL_DIR" ]; then
    cat "$FOUND_WHEEL_DIR"
    return
  fi

  if [ -d "$SEARCH_USER_HOME/.cache/codex-runtimes" ]; then
    find "$SEARCH_USER_HOME/.cache/codex-runtimes" -path '*/ensurepip/_bundled' -type d 2>/dev/null | while IFS= read -r CANDIDATE_WHEEL_DIR; do
      if [ ! -s "$FOUND_WHEEL_DIR" ] && wheel_dir_has_required_python_wheels "$CANDIDATE_WHEEL_DIR"; then
        printf 'host_codex_runtime_ensurepip_bundle:%s\n' "$CANDIDATE_WHEEL_DIR" > "$FOUND_WHEEL_DIR"
      fi
    done
  fi
  if [ -s "$FOUND_WHEEL_DIR" ]; then
    cat "$FOUND_WHEEL_DIR"
  fi
}

copy_python_wheels() {
  PYTHON_WHEEL_STATUS="not_found"
  PYTHON_WHEEL_SOURCE_KIND="none"
  PIP_WHEEL_NAME=""
  PIP_WHEEL_SHA256=""
  SETUPTOOLS_WHEEL_NAME=""
  SETUPTOOLS_WHEEL_SHA256=""
  WHEEL_PACKAGE_STATUS="not_found"
  WHEEL_PACKAGE_SOURCE_KIND="none"
  WHEEL_PACKAGE_NAME=""
  WHEEL_PACKAGE_SHA256=""

  WHEEL_SELECTION=$(detect_python_wheel_dir || true)
  if [ -z "$WHEEL_SELECTION" ]; then
    return
  fi

  PYTHON_WHEEL_SOURCE_KIND=${WHEEL_SELECTION%%:*}
  PYTHON_WHEEL_SOURCE_DIR=${WHEEL_SELECTION#*:}
  PIP_WHEEL=$(find "$PYTHON_WHEEL_SOURCE_DIR" -maxdepth 1 -name 'pip-*.whl' -type f -print 2>/dev/null | sort | tail -n 1)
  SETUPTOOLS_WHEEL=$(find "$PYTHON_WHEEL_SOURCE_DIR" -maxdepth 1 -name 'setuptools-*.whl' -type f -print 2>/dev/null | sort | tail -n 1)
  WHEEL_PACKAGE_SELECTION=$(detect_wheel_package_file || true)
  if [ -n "$WHEEL_PACKAGE_SELECTION" ]; then
    WHEEL_PACKAGE_SOURCE_KIND=${WHEEL_PACKAGE_SELECTION%%:*}
    WHEEL_PACKAGE_FILE=${WHEEL_PACKAGE_SELECTION#*:}
  else
    WHEEL_PACKAGE_FILE=""
  fi
  if [ -z "$PIP_WHEEL" ] || [ -z "$SETUPTOOLS_WHEEL" ] || [ -z "$WHEEL_PACKAGE_FILE" ]; then
    PYTHON_WHEEL_STATUS="not_found"
    PYTHON_WHEEL_SOURCE_KIND="none"
    return
  fi

  GUEST_WHEEL_DIR="$DATA_MOUNT/usr/local/whoathere/python-wheels"
  install -d -o root -g wheel -m 0755 "$GUEST_WHEEL_DIR"
  install -o root -g wheel -m 0644 "$PIP_WHEEL" "$GUEST_WHEEL_DIR/$(basename "$PIP_WHEEL")"
  install -o root -g wheel -m 0644 "$SETUPTOOLS_WHEEL" "$GUEST_WHEEL_DIR/$(basename "$SETUPTOOLS_WHEEL")"
  install -o root -g wheel -m 0644 "$WHEEL_PACKAGE_FILE" "$GUEST_WHEEL_DIR/$(basename "$WHEEL_PACKAGE_FILE")"
  PYTHON_WHEEL_STATUS="installed"
  PIP_WHEEL_NAME=$(basename "$PIP_WHEEL")
  PIP_WHEEL_SHA256=$(shasum -a 256 "$PIP_WHEEL" | awk '{print $1}')
  SETUPTOOLS_WHEEL_NAME=$(basename "$SETUPTOOLS_WHEEL")
  SETUPTOOLS_WHEEL_SHA256=$(shasum -a 256 "$SETUPTOOLS_WHEEL" | awk '{print $1}')
  WHEEL_PACKAGE_STATUS="installed"
  WHEEL_PACKAGE_NAME=$(basename "$WHEEL_PACKAGE_FILE")
  WHEEL_PACKAGE_SHA256=$(shasum -a 256 "$WHEEL_PACKAGE_FILE" | awk '{print $1}')
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
copy_python_runtime
copy_python_wheels

cat > "$RECEIPT_PATH" <<EOF
{
  "schema_version": "whoathere.macos_vm.guest_provisioning.v1",
  "method": "offline_root_owned_launchdaemon",
  "agent_path": "/usr/local/whoathere/whoathere-guest-ready",
  "launchdaemon_path": "/Library/LaunchDaemons/com.whoathere.guest-ready.plist",
  "agent_sha256": "sha256:$AGENT_DIGEST",
  "offline_python_runtime_status": "$PYTHON_RUNTIME_STATUS",
  "offline_python_runtime_source_kind": "$PYTHON_RUNTIME_SOURCE_KIND",
  "offline_python_runtime_name": "$PYTHON_RUNTIME_NAME",
  "offline_python_runtime_python_sha256": "$PYTHON_RUNTIME_PYTHON_SHA256",
  "offline_python_runtime_file_count": $PYTHON_RUNTIME_FILE_COUNT,
  "offline_python_runtime_size_kib": $PYTHON_RUNTIME_SIZE_KIB,
  "offline_python_wheels_status": "$PYTHON_WHEEL_STATUS",
  "offline_python_wheels_source_kind": "$PYTHON_WHEEL_SOURCE_KIND",
  "pip_wheel_name": "$PIP_WHEEL_NAME",
  "pip_wheel_sha256": "$PIP_WHEEL_SHA256",
  "setuptools_wheel_name": "$SETUPTOOLS_WHEEL_NAME",
  "setuptools_wheel_sha256": "$SETUPTOOLS_WHEEL_SHA256",
  "wheel_package_status": "$WHEEL_PACKAGE_STATUS",
  "wheel_package_source_kind": "$WHEEL_PACKAGE_SOURCE_KIND",
  "wheel_package_name": "$WHEEL_PACKAGE_NAME",
  "wheel_package_sha256": "$WHEEL_PACKAGE_SHA256",
  "high_risk_package_execution_enabled": false,
  "host_home_mounted": false,
  "host_secrets_mounted": false
}
EOF
chmod 0644 "$RECEIPT_PATH"

echo "guest_readiness_provisioned=true"
echo "state_dir=$STATE_DIR"
echo "agent_sha256=sha256:$AGENT_DIGEST"
echo "offline_python_runtime_status=$PYTHON_RUNTIME_STATUS"
echo "offline_python_runtime_source_kind=$PYTHON_RUNTIME_SOURCE_KIND"
echo "offline_python_runtime_name=$PYTHON_RUNTIME_NAME"
echo "offline_python_wheels_status=$PYTHON_WHEEL_STATUS"
echo "offline_python_wheels_source_kind=$PYTHON_WHEEL_SOURCE_KIND"
echo "wheel_package_status=$WHEEL_PACKAGE_STATUS"
echo "wheel_package_source_kind=$WHEEL_PACKAGE_SOURCE_KIND"
echo "next_start=$HELPER_ROOT/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper start --state-dir $STATE_DIR --execute --json"
