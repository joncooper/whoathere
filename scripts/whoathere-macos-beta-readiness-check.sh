#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${WHOATHERE_DIST_DIR:-"$REPO_ROOT/dist"}
STATE_DIR=${WHOATHERE_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}
ARCHIVE=""
VERSION=""
REPORT_PATH=""

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-macos-beta-readiness-check.sh [--version <git-sha>] [--archive <preview.tar.gz>] [--state-dir <dir>] [--report <path>]

Checks whether a packaged Apple Silicon macOS local beta archive has enough local evidence to be
called ready. This script verifies the archive checksum, Developer ID signatures, Apple notary
status, clean-install qualification receipt, and the archive's own `whoathere doctor --json`
release gate against the chosen VM state directory.

Exit codes:
  0  ready
  20 not ready, with reason codes printed
  64 invalid usage
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      VERSION=$2
      shift 2
      ;;
    --version=*)
      VERSION=${1#--version=}
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
    --state-dir)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      STATE_DIR=$2
      shift 2
      ;;
    --state-dir=*)
      STATE_DIR=${1#--state-dir=}
      shift
      ;;
    --report)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      REPORT_PATH=$2
      shift 2
      ;;
    --report=*)
      REPORT_PATH=${1#--report=}
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

json_field() {
  /usr/bin/plutil -extract "$1" raw -o - "$2" 2>/dev/null || true
}

json_fragment() {
  /usr/bin/plutil -extract "$1" json -o - "$2" 2>/dev/null || true
}

resolve_archive() {
  if [ -z "$ARCHIVE" ]; then
    if [ -n "$VERSION" ]; then
      ARCHIVE="$DIST_DIR/whoathere-macos-arm64-preview-$VERSION.tar.gz"
    else
      ARCHIVE=$(ls -t "$DIST_DIR"/whoathere-macos-arm64-preview-*.tar.gz 2>/dev/null | head -n 1 || true)
    fi
  fi
  if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
    echo "archive_missing=$ARCHIVE" >&2
    exit 64
  fi
  ARCHIVE=$(CDPATH= cd -- "$(dirname -- "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")
  PACKAGE_NAME=$(basename "$ARCHIVE" .tar.gz)
  VERSION=${PACKAGE_NAME#whoathere-macos-arm64-preview-}
  if [ -z "$REPORT_PATH" ]; then
    REPORT_PATH="$DIST_DIR/$PACKAGE_NAME-six-stage-readiness.txt"
  fi
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print "sha256:" $1}'
}

require_file() {
  if [ ! -f "$1" ]; then
    printf '%s=false\n' "$2"
    return 1
  fi
  printf '%s=true\n' "$2"
}

resolve_archive

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-beta-readiness.XXXXXX")
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

PACKAGE_DIR="$WORK_DIR/$PACKAGE_NAME"
CHECKSUM="$ARCHIVE.sha256"
NOTARY_JSON="$DIST_DIR/$PACKAGE_NAME-notarization.zip.notarytool.json"
CLEAN_INSTALL_RECEIPT="$DIST_DIR/$PACKAGE_NAME-clean-install-qualification.json"
DOCTOR_JSON="$WORK_DIR/doctor.json"
REPORT_TMP="$REPORT_PATH.$$"

checksum_verified=false
archive_sha256=$(sha256_file "$ARCHIVE")
if [ -f "$CHECKSUM" ]; then
  (
    cd "$(dirname "$ARCHIVE")"
    shasum -a 256 -c "$(basename "$CHECKSUM")" >/dev/null
  )
  checksum_verified=true
fi

tar -xzf "$ARCHIVE" -C "$WORK_DIR"
CLI="$PACKAGE_DIR/bin/whoathere"
HELPER="$PACKAGE_DIR/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
if [ ! -x "$CLI" ] || [ ! -x "$HELPER" ]; then
  echo "packaged_cli_or_helper_missing=true" >&2
  exit 64
fi

cli_signature_valid=false
helper_signature_valid=false
if /usr/bin/codesign --verify --strict --verbose=2 "$CLI" >/dev/null 2>&1; then
  cli_signature_valid=true
fi
if /usr/bin/codesign --verify --strict --verbose=2 "$HELPER" >/dev/null 2>&1; then
  helper_signature_valid=true
fi

notarytool_status=""
notarytool_id=""
notary_accepted=false
if [ -f "$NOTARY_JSON" ]; then
  notarytool_status=$(json_field status "$NOTARY_JSON")
  notarytool_id=$(json_field id "$NOTARY_JSON")
  if [ "$notarytool_status" = "Accepted" ] && [ -n "$notarytool_id" ]; then
    notary_accepted=true
  fi
fi

clean_install_qualified=false
clean_install_notarization_verified=false
if [ -f "$CLEAN_INSTALL_RECEIPT" ]; then
  clean_install_qualified=$(json_field qualified "$CLEAN_INSTALL_RECEIPT")
  clean_install_notarization_verified=$(json_field notarization_verified "$CLEAN_INSTALL_RECEIPT")
fi

set +e
"$CLI" doctor --json --state-dir "$STATE_DIR" --helper "$HELPER" > "$DOCTOR_JSON" 2>"$WORK_DIR/doctor.stderr"
doctor_status=$?
set -e

doctor_release_ready=false
doctor_blockers=""
if [ "$doctor_status" -eq 0 ]; then
  doctor_release_ready=$(json_field release_ready "$DOCTOR_JSON")
  doctor_blockers=$(json_fragment release_blocking_reason_codes "$DOCTOR_JSON")
fi

ready=false
exit_code=20
if [ "$checksum_verified" = "true" ] \
  && [ "$cli_signature_valid" = "true" ] \
  && [ "$helper_signature_valid" = "true" ] \
  && [ "$notary_accepted" = "true" ] \
  && [ "$clean_install_qualified" = "true" ] \
  && [ "$clean_install_notarization_verified" = "true" ] \
  && [ "$doctor_release_ready" = "true" ]; then
  ready=true
  exit_code=0
fi

mkdir -p "$(dirname "$REPORT_PATH")"
{
  printf 'whoathere_macos_beta_readiness=true\n'
  printf 'ready=%s\n' "$ready"
  printf 'version=%s\n' "$VERSION"
  printf 'archive=%s\n' "$ARCHIVE"
  printf 'archive_sha256=%s\n' "$archive_sha256"
  printf 'checksum_verified=%s\n' "$checksum_verified"
  printf 'cli_signature_valid=%s\n' "$cli_signature_valid"
  printf 'helper_signature_valid=%s\n' "$helper_signature_valid"
  printf 'notary_accepted=%s\n' "$notary_accepted"
  printf 'notarytool_status=%s\n' "$notarytool_status"
  printf 'notarytool_id=%s\n' "$notarytool_id"
  printf 'clean_install_qualified=%s\n' "$clean_install_qualified"
  printf 'clean_install_notarization_verified=%s\n' "$clean_install_notarization_verified"
  printf 'state_dir=%s\n' "$STATE_DIR"
  printf 'doctor_status=%s\n' "$doctor_status"
  printf 'doctor_release_ready=%s\n' "$doctor_release_ready"
  printf 'doctor_release_blocking_reason_codes=%s\n' "$doctor_blockers"
  printf 'report_path=%s\n' "$REPORT_PATH"
} | tee "$REPORT_TMP"
mv "$REPORT_TMP" "$REPORT_PATH"

exit "$exit_code"
