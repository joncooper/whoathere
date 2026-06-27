#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKAGE_ROOT=${WHOATHERE_PACKAGE_ROOT:-"$SCRIPT_DIR"}
PACKAGE_NAME=$(basename "$PACKAGE_ROOT")
INSTALL_PREFIX=${WHOATHERE_INSTALL_PREFIX:-"$HOME/.whoathere"}
DRY_RUN=false
FORCE=false

usage() {
  cat >&2 <<'EOF'
usage:
  ./install-macos-preview.sh [--dry-run] [--force] [--prefix <dir>]

Installs the extracted WhoaThere macOS local-first preview for the current user only.
No sudo is used. The installer copies the package under <prefix>/releases and writes a wrapper at
<prefix>/bin/whoathere that points WHOATHERE_MACOS_VM_HELPER at the packaged helper.
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --prefix)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      INSTALL_PREFIX=$2
      shift 2
      ;;
    --prefix=*)
      INSTALL_PREFIX=${1#--prefix=}
      shift
      ;;
    --help|-h)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

require_host() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "macos_host_required=true" >&2
    exit 64
  fi
  if [ "$(uname -m)" != "arm64" ]; then
    echo "apple_silicon_arm64_required=true" >&2
    exit 64
  fi
}

require_package_layout() {
  CLI="$PACKAGE_ROOT/bin/whoathere"
  HELPER="$PACKAGE_ROOT/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  PROVISIONER="$PACKAGE_ROOT/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh"
  VALIDATOR="$PACKAGE_ROOT/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh"

  if [ ! -x "$CLI" ]; then
    echo "packaged_cli_missing_or_not_executable=$CLI" >&2
    exit 64
  fi
  if [ ! -x "$HELPER" ]; then
    echo "packaged_helper_missing_or_not_executable=$HELPER" >&2
    exit 64
  fi
  if [ ! -x "$PROVISIONER" ]; then
    echo "packaged_provisioner_missing_or_not_executable=$PROVISIONER" >&2
    exit 64
  fi
  if [ ! -x "$VALIDATOR" ]; then
    echo "packaged_validator_missing_or_not_executable=$VALIDATOR" >&2
    exit 64
  fi
  sh -n "$PROVISIONER"
  sh -n "$VALIDATOR"
  /usr/bin/codesign --verify --strict --verbose=2 "$CLI" >/dev/null
  /usr/bin/codesign --verify --strict --verbose=2 "$HELPER" >/dev/null
}

safe_install_prefix() {
  if [ -z "$INSTALL_PREFIX" ] || [ "$INSTALL_PREFIX" = "/" ]; then
    echo "unsafe_install_prefix=$INSTALL_PREFIX" >&2
    exit 64
  fi
}

render_plan() {
  RELEASE_DIR="$INSTALL_PREFIX/releases/$PACKAGE_NAME"
  WRAPPER_DIR="$INSTALL_PREFIX/bin"
  WRAPPER="$WRAPPER_DIR/whoathere"
  INSTALLED_HELPER="$RELEASE_DIR/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"

  echo "whoathere_install_macos_preview=true"
  echo "dry_run=$DRY_RUN"
  echo "force=$FORCE"
  echo "package_root=$PACKAGE_ROOT"
  echo "package_name=$PACKAGE_NAME"
  echo "install_prefix=$INSTALL_PREFIX"
  echo "release_dir=$RELEASE_DIR"
  echo "wrapper=$WRAPPER"
  echo "installed_helper=$INSTALLED_HELPER"
}

shell_quote() {
  printf "'"
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}

write_wrapper() {
  WRAPPER_TMP="$WRAPPER.$$"
  QUOTED_RELEASE_DIR=$(shell_quote "$RELEASE_DIR")
  QUOTED_INSTALLED_HELPER=$(shell_quote "$INSTALLED_HELPER")
  cat > "$WRAPPER_TMP" <<EOF
#!/bin/sh
WHOATHERE_INSTALL_ROOT=$QUOTED_RELEASE_DIR
if [ -z "\${WHOATHERE_MACOS_VM_HELPER:-}" ]; then
  WHOATHERE_MACOS_VM_HELPER=$QUOTED_INSTALLED_HELPER
fi
export WHOATHERE_MACOS_VM_HELPER
exec "\$WHOATHERE_INSTALL_ROOT/bin/whoathere" "\$@"
EOF
  chmod 0755 "$WRAPPER_TMP"
  mv "$WRAPPER_TMP" "$WRAPPER"
}

install_package() {
  if [ -e "$RELEASE_DIR" ] && [ "$FORCE" != "true" ]; then
    echo "release_already_installed=true" >&2
    echo "rerun_with_force=true" >&2
    exit 64
  fi

  mkdir -p "$INSTALL_PREFIX/releases" "$WRAPPER_DIR"
  TMP_RELEASE="$INSTALL_PREFIX/releases/.$PACKAGE_NAME.$$"
  rm -rf "$TMP_RELEASE"
  if command -v ditto >/dev/null 2>&1; then
    ditto --noqtn "$PACKAGE_ROOT" "$TMP_RELEASE"
  else
    mkdir -p "$TMP_RELEASE"
    cp -R "$PACKAGE_ROOT"/. "$TMP_RELEASE"/
  fi
  if [ -e "$RELEASE_DIR" ]; then
    rm -rf "$RELEASE_DIR"
  fi
  mv "$TMP_RELEASE" "$RELEASE_DIR"
  write_wrapper
}

require_host
require_package_layout
safe_install_prefix
render_plan

if [ "$DRY_RUN" = "true" ]; then
  echo "install_status=dry_run_not_installed"
  exit 0
fi

install_package
echo "install_status=ok"
echo "next_command=$WRAPPER doctor --json"
