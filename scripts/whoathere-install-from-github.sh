#!/bin/sh
set -eu

REPO=${WHOATHERE_GITHUB_REPO:-joncooper/whoathere}
TAG=${WHOATHERE_GITHUB_TAG:-latest}
PREFIX=${WHOATHERE_INSTALL_PREFIX:-"$HOME/.whoathere"}
FORCE=false
DRY_RUN=false
ARCHIVE_NAME=${WHOATHERE_GITHUB_ARCHIVE:-whoathere-macos-arm64-preview-latest.tar.gz}
CHECKSUM_NAME="$ARCHIVE_NAME.sha256"
KEEP_DOWNLOADS=false

usage() {
  cat >&2 <<'EOF'
usage:
  whoathere-install-from-github.sh [--repo <owner/name>] [--tag <tag|latest>] [--prefix <dir>] [--force] [--dry-run] [--keep]

Downloads the WhoaThere Apple Silicon macOS preview from a GitHub Release, verifies the SHA-256
checksum, extracts it, and runs the packaged user-level installer.

Defaults:
  repo:   joncooper/whoathere, or WHOATHERE_GITHUB_REPO
  tag:    latest, or WHOATHERE_GITHUB_TAG
  prefix: $HOME/.whoathere, or WHOATHERE_INSTALL_PREFIX

The release must publish these assets:
  whoathere-macos-arm64-preview-latest.tar.gz
  whoathere-macos-arm64-preview-latest.tar.gz.sha256
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      REPO=$2
      shift 2
      ;;
    --repo=*)
      REPO=${1#--repo=}
      shift
      ;;
    --tag)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      TAG=$2
      shift 2
      ;;
    --tag=*)
      TAG=${1#--tag=}
      shift
      ;;
    --prefix)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      PREFIX=$2
      shift 2
      ;;
    --prefix=*)
      PREFIX=${1#--prefix=}
      shift
      ;;
    --force)
      FORCE=true
      shift
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --keep)
      KEEP_DOWNLOADS=true
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

release_url() {
  ASSET=$1
  if [ "$TAG" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO" "$ASSET"
  else
    printf 'https://github.com/%s/releases/download/%s/%s\n' "$REPO" "$TAG" "$ASSET"
  fi
}

download() {
  URL=$1
  OUT=$2
  curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 -o "$OUT" "$URL"
}

require_host

ARCHIVE_URL=$(release_url "$ARCHIVE_NAME")
CHECKSUM_URL=$(release_url "$CHECKSUM_NAME")

echo "whoathere_install_from_github=true"
echo "repo=$REPO"
echo "tag=$TAG"
echo "archive_url=$ARCHIVE_URL"
echo "checksum_url=$CHECKSUM_URL"
echo "install_prefix=$PREFIX"
echo "force=$FORCE"
echo "dry_run=$DRY_RUN"

if [ "$DRY_RUN" = "true" ]; then
  echo "install_status=dry_run_not_installed"
  exit 0
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-github-install.XXXXXX")
cleanup() {
  if [ "$KEEP_DOWNLOADS" != "true" ]; then
    rm -rf "$WORK_DIR"
  else
    echo "kept_downloads=$WORK_DIR"
  fi
}
trap cleanup EXIT HUP INT TERM

ARCHIVE_PATH="$WORK_DIR/$ARCHIVE_NAME"
CHECKSUM_PATH="$WORK_DIR/$CHECKSUM_NAME"

download "$ARCHIVE_URL" "$ARCHIVE_PATH"
download "$CHECKSUM_URL" "$CHECKSUM_PATH"

(
  cd "$WORK_DIR"
  shasum -a 256 -c "$CHECKSUM_NAME"
)

PACKAGE_ROOT=$(tar -tzf "$ARCHIVE_PATH" | sed -n '1s#/.*##p')
if tar -tzf "$ARCHIVE_PATH" | grep -E '(^/|(^|/)\.\.(/|$))' >/dev/null; then
  echo "unsafe_archive_paths_detected=true" >&2
  exit 65
fi
case "$PACKAGE_ROOT" in
  ""|.*|*/*)
    echo "unsafe_package_root=$PACKAGE_ROOT" >&2
    exit 65
    ;;
esac

tar -xzf "$ARCHIVE_PATH" -C "$WORK_DIR"
if [ -z "$PACKAGE_ROOT" ] || [ ! -d "$WORK_DIR/$PACKAGE_ROOT" ]; then
  echo "downloaded_package_root_not_found=true" >&2
  exit 65
fi

if [ "$FORCE" = "true" ]; then
  "$WORK_DIR/$PACKAGE_ROOT/install-macos-preview.sh" --prefix "$PREFIX" --force
else
  "$WORK_DIR/$PACKAGE_ROOT/install-macos-preview.sh" --prefix "$PREFIX"
fi

echo "installed_wrapper=$PREFIX/bin/whoathere"
echo "next_command=$PREFIX/bin/whoathere doctor --json"
