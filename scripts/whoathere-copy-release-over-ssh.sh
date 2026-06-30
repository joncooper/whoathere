#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${WHOATHERE_DIST_DIR:-"$REPO_ROOT/dist"}
VERSION=${WHOATHERE_PREVIEW_VERSION:-$(git -C "$REPO_ROOT" rev-parse --short HEAD)}
ARCHIVE="$DIST_DIR/whoathere-macos-arm64-preview-$VERSION.tar.gz"
REMOTE_HOST=
REMOTE_DIR='~/whoathere-release'

usage() {
  cat >&2 <<'EOF'
usage:
  whoathere-copy-release-over-ssh.sh --host <user@host> [--version <version>] [--archive <path>] [--remote-dir <path>]

Copies a WhoaThere macOS preview archive and a portable basename-only SHA-256 sidecar to a
disposable Mac over SSH/SCP. This avoids GitHub authentication on the target host.

The script does not store credentials. Use SSH keys, an agent, or the interactive password prompt
from ssh/scp.
EOF
  exit 64
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --host)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      REMOTE_HOST=$2
      shift 2
      ;;
    --host=*)
      REMOTE_HOST=${1#--host=}
      shift
      ;;
    --version)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      VERSION=$2
      ARCHIVE="$DIST_DIR/whoathere-macos-arm64-preview-$VERSION.tar.gz"
      shift 2
      ;;
    --version=*)
      VERSION=${1#--version=}
      ARCHIVE="$DIST_DIR/whoathere-macos-arm64-preview-$VERSION.tar.gz"
      shift
      ;;
    --archive)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      ARCHIVE=$2
      shift 2
      ;;
    --archive=*)
      ARCHIVE=${1#--archive=}
      shift
      ;;
    --remote-dir)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      REMOTE_DIR=$2
      shift 2
      ;;
    --remote-dir=*)
      REMOTE_DIR=${1#--remote-dir=}
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

if [ -z "$REMOTE_HOST" ]; then
  echo "remote_host_required=true" >&2
  usage
fi
if [ ! -f "$ARCHIVE" ]; then
  echo "archive_missing=$ARCHIVE" >&2
  exit 66
fi
case "$REMOTE_HOST" in
  *[!A-Za-z0-9._@:-]*|"")
    echo "unsafe_remote_host=$REMOTE_HOST" >&2
    exit 64
    ;;
esac
case "$REMOTE_DIR" in
  *"
"*|*".."*)
    echo "unsafe_remote_dir=$REMOTE_DIR" >&2
    exit 64
    ;;
esac

ARCHIVE=$(CDPATH= cd -- "$(dirname -- "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-ssh-release.XXXXXX")
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

ARCHIVE_NAME=$(basename "$ARCHIVE")
CHECKSUM_NAME="$ARCHIVE_NAME.sha256"
cp "$ARCHIVE" "$WORK_DIR/$ARCHIVE_NAME"
(
  cd "$WORK_DIR"
  shasum -a 256 "$ARCHIVE_NAME" > "$CHECKSUM_NAME"
  shasum -a 256 -c "$CHECKSUM_NAME"
)

REMOTE_DIR_QUOTED=$(shell_quote "$REMOTE_DIR")
ssh "$REMOTE_HOST" "mkdir -p -- $REMOTE_DIR_QUOTED"
scp "$WORK_DIR/$ARCHIVE_NAME" "$WORK_DIR/$CHECKSUM_NAME" "$REMOTE_HOST:$REMOTE_DIR/"

echo "whoathere_release_copied=true"
echo "remote_host=$REMOTE_HOST"
echo "remote_dir=$REMOTE_DIR"
echo "archive=$ARCHIVE_NAME"
echo "checksum=$CHECKSUM_NAME"
echo "remote_verify_command=cd $REMOTE_DIR && shasum -a 256 -c $CHECKSUM_NAME"
