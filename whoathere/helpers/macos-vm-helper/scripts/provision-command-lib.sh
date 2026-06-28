#!/bin/sh

whoathere_shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

whoathere_default_helper_path() {
  HELPER_ROOT_FOR_PATH=$1
  if [ -n "${WHOATHERE_MACOS_VM_HELPER:-}" ]; then
    printf '%s\n' "$WHOATHERE_MACOS_VM_HELPER"
    return
  fi

  RELEASE_HELPER="$HELPER_ROOT_FOR_PATH/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  DEBUG_HELPER="$HELPER_ROOT_FOR_PATH/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper"
  if [ -x "$RELEASE_HELPER" ]; then
    printf '%s\n' "$RELEASE_HELPER"
    return
  fi

  printf '%s\n' "$DEBUG_HELPER"
}

whoathere_user_home_default() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    USER_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    if [ -n "$USER_HOME" ]; then
      printf '%s\n' "$USER_HOME"
      return
    fi
  fi

  printf '%s\n' "$HOME"
}

whoathere_python_runtime_dir_is_usable() {
  PYTHON_RUNTIME_CHECK_DIR=$1
  [ -x "$PYTHON_RUNTIME_CHECK_DIR/bin/python3" ]
}

whoathere_detect_python_runtime_dir() {
  if [ -n "${WHOATHERE_PYTHON_RUNTIME_DIR:-}" ] && whoathere_python_runtime_dir_is_usable "$WHOATHERE_PYTHON_RUNTIME_DIR"; then
    printf '%s\n' "$WHOATHERE_PYTHON_RUNTIME_DIR"
    return
  fi

  SEARCH_USER_HOME=$(whoathere_user_home_default)
  for CANDIDATE_RUNTIME_DIR in \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.11.11-macos-aarch64-none" \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.12.11-macos-aarch64-none" \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.13.2-macos-aarch64-none" \
    "$SEARCH_USER_HOME/.local/share/uv/python/cpython-3.10.20-macos-aarch64-none"; do
    if [ -d "$CANDIDATE_RUNTIME_DIR" ] && whoathere_python_runtime_dir_is_usable "$CANDIDATE_RUNTIME_DIR"; then
      printf '%s\n' "$CANDIDATE_RUNTIME_DIR"
      return
    fi
  done
}

whoathere_python_wheel_dir_is_usable() {
  PYTHON_WHEEL_CHECK_DIR=$1
  [ -n "$(find "$PYTHON_WHEEL_CHECK_DIR" -maxdepth 1 -name 'pip-*.whl' -type f -print -quit 2>/dev/null)" ] \
    && [ -n "$(find "$PYTHON_WHEEL_CHECK_DIR" -maxdepth 1 -name 'setuptools-*.whl' -type f -print -quit 2>/dev/null)" ]
}

whoathere_detect_python_wheel_dir() {
  if [ -n "${WHOATHERE_PYTHON_WHEEL_DIR:-}" ] && whoathere_python_wheel_dir_is_usable "$WHOATHERE_PYTHON_WHEEL_DIR"; then
    printf '%s\n' "$WHOATHERE_PYTHON_WHEEL_DIR"
    return
  fi

  SEARCH_USER_HOME=$(whoathere_user_home_default)
  FOUND_WHEEL_DIR="${TMPDIR:-/tmp}/whoathere-python-wheel-dir.$$"
  : > "$FOUND_WHEEL_DIR"
  if [ -d "$SEARCH_USER_HOME/.local/share/uv/python" ]; then
    find "$SEARCH_USER_HOME/.local/share/uv/python" -path '*/ensurepip/_bundled' -type d 2>/dev/null | while IFS= read -r CANDIDATE_WHEEL_DIR; do
      if [ ! -s "$FOUND_WHEEL_DIR" ] && whoathere_python_wheel_dir_is_usable "$CANDIDATE_WHEEL_DIR"; then
        printf '%s\n' "$CANDIDATE_WHEEL_DIR" > "$FOUND_WHEEL_DIR"
      fi
    done
  fi
  if [ -s "$FOUND_WHEEL_DIR" ]; then
    cat "$FOUND_WHEEL_DIR"
    rm -f "$FOUND_WHEEL_DIR"
    return
  fi
  rm -f "$FOUND_WHEEL_DIR"
}

whoathere_detect_wheel_package_file() {
  if [ -n "${WHOATHERE_WHEEL_PACKAGE_FILE:-}" ] && [ -f "$WHOATHERE_WHEEL_PACKAGE_FILE" ]; then
    printf '%s\n' "$WHOATHERE_WHEEL_PACKAGE_FILE"
    return
  fi

  SEARCH_USER_HOME=$(whoathere_user_home_default)
  FOUND_WHEEL_FILE="${TMPDIR:-/tmp}/whoathere-wheel-package-file.$$"
  : > "$FOUND_WHEEL_FILE"
  if [ -d "$SEARCH_USER_HOME/Library/Caches/pypoetry/artifacts" ]; then
    find "$SEARCH_USER_HOME/Library/Caches/pypoetry/artifacts" -name 'wheel-*.whl' -type f 2>/dev/null | sort | while IFS= read -r CANDIDATE_WHEEL_FILE; do
      if [ ! -s "$FOUND_WHEEL_FILE" ]; then
        printf '%s\n' "$CANDIDATE_WHEEL_FILE" > "$FOUND_WHEEL_FILE"
      fi
    done
  fi
  if [ -s "$FOUND_WHEEL_FILE" ]; then
    cat "$FOUND_WHEEL_FILE"
    rm -f "$FOUND_WHEEL_FILE"
    return
  fi
  rm -f "$FOUND_WHEEL_FILE"

  FOUND_WHEEL_FILE="${TMPDIR:-/tmp}/whoathere-wheel-package-file.$$"
  : > "$FOUND_WHEEL_FILE"
  if [ -d "$SEARCH_USER_HOME/.cache/codex-runtimes" ]; then
    find "$SEARCH_USER_HOME/.cache/codex-runtimes" -name 'wheel-*.whl' -type f 2>/dev/null | sort | while IFS= read -r CANDIDATE_WHEEL_FILE; do
      if [ ! -s "$FOUND_WHEEL_FILE" ]; then
        printf '%s\n' "$CANDIDATE_WHEEL_FILE" > "$FOUND_WHEEL_FILE"
      fi
    done
  fi
  if [ -s "$FOUND_WHEEL_FILE" ]; then
    cat "$FOUND_WHEEL_FILE"
    rm -f "$FOUND_WHEEL_FILE"
    return
  fi
  rm -f "$FOUND_WHEEL_FILE"
}

whoathere_node_runtime_dir_is_usable() {
  NODE_RUNTIME_CHECK_DIR=$1
  [ -x "$NODE_RUNTIME_CHECK_DIR/bin/node" ] && [ -x "$NODE_RUNTIME_CHECK_DIR/bin/npm" ]
}

whoathere_detect_node_runtime_dir() {
  if [ -n "${WHOATHERE_NODE_RUNTIME_DIR:-}" ] && whoathere_node_runtime_dir_is_usable "$WHOATHERE_NODE_RUNTIME_DIR"; then
    printf '%s\n' "$WHOATHERE_NODE_RUNTIME_DIR"
    return
  fi

  SEARCH_USER_HOME=$(whoathere_user_home_default)
  FOUND_NODE_DIR="${TMPDIR:-/tmp}/whoathere-node-runtime-dir.$$"
  : > "$FOUND_NODE_DIR"
  if [ -d "$SEARCH_USER_HOME/.nvm/versions/node" ]; then
    find "$SEARCH_USER_HOME/.nvm/versions/node" -maxdepth 1 -type d -name 'v*' 2>/dev/null | sort | while IFS= read -r CANDIDATE_NODE_DIR; do
      if [ ! -s "$FOUND_NODE_DIR" ] && whoathere_node_runtime_dir_is_usable "$CANDIDATE_NODE_DIR"; then
        printf '%s\n' "$CANDIDATE_NODE_DIR" > "$FOUND_NODE_DIR"
      fi
    done
  fi
  if [ -s "$FOUND_NODE_DIR" ]; then
    cat "$FOUND_NODE_DIR"
    rm -f "$FOUND_NODE_DIR"
    return
  fi
  rm -f "$FOUND_NODE_DIR"

  NODE_BIN=$(command -v node 2>/dev/null || true)
  if [ -n "$NODE_BIN" ]; then
    CANDIDATE_NODE_DIR=$(CDPATH= cd -- "$(dirname -- "$NODE_BIN")/.." && pwd)
    if whoathere_node_runtime_dir_is_usable "$CANDIDATE_NODE_DIR"; then
      printf '%s\n' "$CANDIDATE_NODE_DIR"
    fi
  fi
}

whoathere_uv_binary_is_usable() {
  UV_BINARY_CHECK_PATH=$1
  [ -x "$UV_BINARY_CHECK_PATH" ]
}

whoathere_detect_uv_binary() {
  if [ -n "${WHOATHERE_UV_BINARY:-}" ] && whoathere_uv_binary_is_usable "$WHOATHERE_UV_BINARY"; then
    printf '%s\n' "$WHOATHERE_UV_BINARY"
    return
  fi

  SEARCH_USER_HOME=$(whoathere_user_home_default)
  if [ -x "$SEARCH_USER_HOME/.local/bin/uv" ]; then
    printf '%s\n' "$SEARCH_USER_HOME/.local/bin/uv"
    return
  fi

  UV_BIN=$(command -v uv 2>/dev/null || true)
  if [ -n "$UV_BIN" ] && whoathere_uv_binary_is_usable "$UV_BIN"; then
    printf '%s\n' "$UV_BIN"
  fi
}

whoathere_reprovision_command() {
  HELPER_ROOT_FOR_COMMAND=$1
  STATE_DIR_FOR_COMMAND=$2
  PYTHON_RUNTIME_DIR_FOR_COMMAND=$(whoathere_detect_python_runtime_dir || true)
  PYTHON_WHEEL_DIR_FOR_COMMAND=$(whoathere_detect_python_wheel_dir || true)
  WHEEL_PACKAGE_FILE_FOR_COMMAND=$(whoathere_detect_wheel_package_file || true)
  NODE_RUNTIME_DIR_FOR_COMMAND=$(whoathere_detect_node_runtime_dir || true)
  UV_BINARY_FOR_COMMAND=$(whoathere_detect_uv_binary || true)

  printf 'sudo'
  if [ -n "$PYTHON_RUNTIME_DIR_FOR_COMMAND" ]; then
    printf ' WHOATHERE_PYTHON_RUNTIME_DIR=%s' "$(whoathere_shell_quote "$PYTHON_RUNTIME_DIR_FOR_COMMAND")"
  fi
  if [ -n "$PYTHON_WHEEL_DIR_FOR_COMMAND" ]; then
    printf ' WHOATHERE_PYTHON_WHEEL_DIR=%s' "$(whoathere_shell_quote "$PYTHON_WHEEL_DIR_FOR_COMMAND")"
  fi
  if [ -n "$WHEEL_PACKAGE_FILE_FOR_COMMAND" ]; then
    printf ' WHOATHERE_WHEEL_PACKAGE_FILE=%s' "$(whoathere_shell_quote "$WHEEL_PACKAGE_FILE_FOR_COMMAND")"
  fi
  if [ -n "$NODE_RUNTIME_DIR_FOR_COMMAND" ]; then
    printf ' WHOATHERE_NODE_RUNTIME_DIR=%s' "$(whoathere_shell_quote "$NODE_RUNTIME_DIR_FOR_COMMAND")"
  fi
  if [ -n "$UV_BINARY_FOR_COMMAND" ]; then
    printf ' WHOATHERE_UV_BINARY=%s' "$(whoathere_shell_quote "$UV_BINARY_FOR_COMMAND")"
  fi
  printf ' %s %s\n' \
    "$(whoathere_shell_quote "$HELPER_ROOT_FOR_COMMAND/scripts/provision-guest-readiness.sh")" \
    "$(whoathere_shell_quote "$STATE_DIR_FOR_COMMAND")"
}
