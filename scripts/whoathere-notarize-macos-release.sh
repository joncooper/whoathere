#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MODE=${1:-}
ARCHIVE=${2:-}
NOTARY_PROFILE=${WHOATHERE_NOTARY_PROFILE:-}
NOTARY_APPLE_ID=${WHOATHERE_NOTARY_APPLE_ID:-}
NOTARY_TEAM_ID=${WHOATHERE_NOTARY_TEAM_ID:-}
NOTARY_PASSWORD=${WHOATHERE_NOTARY_PASSWORD:-}
RELEASE_STATE_DIR=${WHOATHERE_RELEASE_STATE_DIR:-${WHOATHERE_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}}
RELEASE_NOTARIZATION_RECEIPT=${WHOATHERE_RELEASE_NOTARIZATION_RECEIPT:-"$RELEASE_STATE_DIR/bundle/release-notarization.json"}
WORK_ROOT=""

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-notarize-macos-release.sh --dry-run /path/to/whoathere-macos-arm64-preview-<version>.tar.gz
  scripts/whoathere-notarize-macos-release.sh --submit  /path/to/whoathere-macos-arm64-preview-<version>.tar.gz

Environment for --submit:
  WHOATHERE_NOTARY_PROFILE=<keychain-profile>
    or
  WHOATHERE_NOTARY_APPLE_ID=<apple-id>
  WHOATHERE_NOTARY_TEAM_ID=<team-id>
  WHOATHERE_NOTARY_PASSWORD=<app-specific-password>

The archive must already contain Developer ID signed binaries. Ad-hoc signatures are accepted for
dry-run packaging checks but rejected for notarization submission.
EOF
  exit 64
}

cleanup() {
  if [ -n "$WORK_ROOT" ]; then
    rm -rf "$WORK_ROOT"
  fi
}
trap cleanup EXIT HUP INT TERM

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

require_mode_and_archive() {
  case "$MODE" in
    --dry-run|--submit) ;;
    *) usage ;;
  esac
  if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
    echo "archive_not_found=$ARCHIVE" >&2
    usage
  fi
  case "$ARCHIVE" in
    *.tar.gz) ;;
    *)
      echo "archive_must_be_tar_gz=$ARCHIVE" >&2
      exit 64
      ;;
  esac
}

verify_archive_checksum_if_present() {
  if [ -f "$ARCHIVE.sha256" ]; then
    shasum -a 256 -c "$ARCHIVE.sha256"
  else
    echo "archive_checksum_sidecar_present=false"
  fi
}

codesign_summary() {
  /usr/bin/codesign -dv --verbose=4 "$1" 2>&1 || true
}

codesign_is_adhoc() {
  codesign_summary "$1" | grep -q 'Signature=adhoc'
}

codesign_signature_kind() {
  SUMMARY=$(codesign_summary "$1")
  if printf '%s\n' "$SUMMARY" | grep -q 'Signature=adhoc'; then
    echo "adhoc"
  elif printf '%s\n' "$SUMMARY" | grep -q '^Authority=Developer ID Application:'; then
    echo "developer_id_application"
  elif printf '%s\n' "$SUMMARY" | grep -q '^Authority=Apple Development:'; then
    echo "apple_development"
  else
    echo "signed_unknown"
  fi
}

require_extracted_artifacts() {
  PACKAGE_NAME=$(basename "$ARCHIVE" .tar.gz)
  EXTRACTED_ROOT="$WORK_ROOT/$PACKAGE_NAME"
  CLI="$EXTRACTED_ROOT/bin/whoathere"
  HELPER="$EXTRACTED_ROOT/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  VALIDATOR="$EXTRACTED_ROOT/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh"

  if [ ! -x "$CLI" ]; then
    echo "extracted_cli_missing_or_not_executable=$CLI" >&2
    exit 1
  fi
  if [ ! -x "$HELPER" ]; then
    echo "extracted_helper_missing_or_not_executable=$HELPER" >&2
    exit 1
  fi
  if [ ! -x "$VALIDATOR" ]; then
    echo "extracted_npm_uv_validator_missing_or_not_executable=$VALIDATOR" >&2
    exit 1
  fi

  sh -n "$VALIDATOR"
  /usr/bin/codesign --verify --strict --verbose=2 "$CLI" >/dev/null
  /usr/bin/codesign --verify --strict --verbose=2 "$HELPER" >/dev/null

  CLI_ADHOC=false
  HELPER_ADHOC=false
  CLI_SIGNATURE_KIND=$(codesign_signature_kind "$CLI")
  HELPER_SIGNATURE_KIND=$(codesign_signature_kind "$HELPER")
  if [ "$CLI_SIGNATURE_KIND" = "adhoc" ]; then
    CLI_ADHOC=true
  fi
  if [ "$HELPER_SIGNATURE_KIND" = "adhoc" ]; then
    HELPER_ADHOC=true
  fi
}

write_notarization_zip() {
  ARCHIVE_DIR=$(CDPATH= cd -- "$(dirname -- "$ARCHIVE")" && pwd)
  PACKAGE_NAME=$(basename "$ARCHIVE" .tar.gz)
  NOTARY_ZIP=${WHOATHERE_NOTARY_ZIP:-"$ARCHIVE_DIR/$PACKAGE_NAME-notarization.zip"}
  rm -f "$NOTARY_ZIP"
  (
    cd "$WORK_ROOT"
    /usr/bin/ditto -c -k --keepParent "$PACKAGE_NAME" "$NOTARY_ZIP"
  )
  test -s "$NOTARY_ZIP"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print "sha256:" $1}'
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_field() {
  /usr/bin/plutil -extract "$1" raw -o - "$RESULT_PATH" 2>/dev/null || true
}

write_release_notarization_receipt() {
  NOTARY_STATUS=$(json_field status)
  NOTARY_ID=$(json_field id)
  NOTARY_MESSAGE=$(json_field message)

  if [ "$NOTARY_STATUS" != "Accepted" ]; then
    echo "notarization_receipt_written=false"
    echo "notarization_blocker=notarytool_status_not_accepted"
    exit 70
  fi
  if [ -z "$NOTARY_ID" ]; then
    echo "notarization_receipt_written=false"
    echo "notarization_blocker=notarytool_id_missing"
    exit 70
  fi

  RECEIPT_DIR=$(dirname "$RELEASE_NOTARIZATION_RECEIPT")
  mkdir -p "$RECEIPT_DIR"
  RECEIPT_TMP="$RELEASE_NOTARIZATION_RECEIPT.$$"
  CREATED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  CREATED_AT_UNIX=$(date -u '+%s')
  ARCHIVE_DIGEST=$(sha256_file "$ARCHIVE")
  NOTARY_ZIP_DIGEST=$(sha256_file "$NOTARY_ZIP")
  CLI_DIGEST=$(sha256_file "$CLI")
  HELPER_DIGEST=$(sha256_file "$HELPER")
  PACKAGE_NAME=$(basename "$ARCHIVE" .tar.gz)
  cat > "$RECEIPT_TMP" <<EOF
{
  "schema_version": "whoathere.macos_vm.release_notarization.v1",
  "artifact_name": "$(json_escape "$PACKAGE_NAME")",
  "archive_sha256": "$(json_escape "$ARCHIVE_DIGEST")",
  "notarization_zip_sha256": "$(json_escape "$NOTARY_ZIP_DIGEST")",
  "cli_sha256": "$(json_escape "$CLI_DIGEST")",
  "helper_sha256": "$(json_escape "$HELPER_DIGEST")",
  "notarytool_status": "$(json_escape "$NOTARY_STATUS")",
  "notarytool_id": "$(json_escape "$NOTARY_ID")",
  "notarytool_message": "$(json_escape "$NOTARY_MESSAGE")",
  "cli_signature_kind": "$(json_escape "$CLI_SIGNATURE_KIND")",
  "helper_signature_kind": "$(json_escape "$HELPER_SIGNATURE_KIND")",
  "stapling_supported_for_archive": false,
  "created_at": "$(json_escape "$CREATED_AT")",
  "created_at_unix_seconds": $CREATED_AT_UNIX
}
EOF
  mv "$RECEIPT_TMP" "$RELEASE_NOTARIZATION_RECEIPT"
  "$CLI" vm attest-receipt \
    --state-dir "$RELEASE_STATE_DIR" \
    --receipt "$RELEASE_NOTARIZATION_RECEIPT" \
    --kind release-notarization >/dev/null
  echo "notarization_receipt=$RELEASE_NOTARIZATION_RECEIPT"
  echo "notarization_receipt_written=true"
}

notary_credentials_ready() {
  if [ -n "$NOTARY_PROFILE" ]; then
    return 0
  fi
  if [ -n "$NOTARY_APPLE_ID" ] && [ -n "$NOTARY_TEAM_ID" ] && [ -n "$NOTARY_PASSWORD" ]; then
    return 0
  fi
  return 1
}

submit_notarization() {
  if [ "$CLI_ADHOC" = "true" ] || [ "$HELPER_ADHOC" = "true" ]; then
    echo "notarization_submit_ready=false"
    echo "notarization_blocker=adhoc_signature_present"
    exit 64
  fi
  if [ "$CLI_SIGNATURE_KIND" != "developer_id_application" ] || [ "$HELPER_SIGNATURE_KIND" != "developer_id_application" ]; then
    echo "notarization_submit_ready=false"
    echo "notarization_blocker=developer_id_application_signature_required"
    exit 64
  fi
  if ! notary_credentials_ready; then
    echo "notarization_submit_ready=false"
    echo "notarization_blocker=notary_credentials_missing"
    exit 64
  fi

  RESULT_PATH=${WHOATHERE_NOTARY_RESULT_PATH:-"$NOTARY_ZIP.notarytool.json"}
  if [ -n "$NOTARY_PROFILE" ]; then
    xcrun notarytool submit "$NOTARY_ZIP" --wait --output-format json --keychain-profile "$NOTARY_PROFILE" > "$RESULT_PATH"
  else
    xcrun notarytool submit "$NOTARY_ZIP" --wait --output-format json --apple-id "$NOTARY_APPLE_ID" --team-id "$NOTARY_TEAM_ID" --password "$NOTARY_PASSWORD" > "$RESULT_PATH"
  fi
  echo "notarization_result=$RESULT_PATH"
  write_release_notarization_receipt
  echo "notarization_status=submitted"
}

require_host
require_mode_and_archive
verify_archive_checksum_if_present
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-notary.XXXXXX")
tar -xzf "$ARCHIVE" -C "$WORK_ROOT"
require_extracted_artifacts
write_notarization_zip

SUBMIT_READY=true
if [ "$CLI_ADHOC" = "true" ] || [ "$HELPER_ADHOC" = "true" ]; then
  SUBMIT_READY=false
fi
if [ "$CLI_SIGNATURE_KIND" != "developer_id_application" ] || [ "$HELPER_SIGNATURE_KIND" != "developer_id_application" ]; then
  SUBMIT_READY=false
fi
if ! notary_credentials_ready; then
  SUBMIT_READY=false
fi

echo "notarization_archive=$ARCHIVE"
echo "notarization_zip=$NOTARY_ZIP"
echo "cli_signature_kind=$CLI_SIGNATURE_KIND"
echo "helper_signature_kind=$HELPER_SIGNATURE_KIND"
echo "cli_signature_adhoc=$CLI_ADHOC"
echo "helper_signature_adhoc=$HELPER_ADHOC"
echo "notary_credentials_configured=$(notary_credentials_ready && echo true || echo false)"
echo "notarization_submit_ready=$SUBMIT_READY"
echo "stapling_supported_for_archive=false"

if [ "$MODE" = "--submit" ]; then
  submit_notarization
else
  echo "notarization_status=dry_run_not_submitted"
fi
