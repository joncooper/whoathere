#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
ARCHIVE=""
RECEIPT_PATH=""
NOTARIZATION_RECEIPT=""
ALLOW_ADHOC=false
ALLOW_UNNOTARIZED=false
KEEP_WORK=false
WORK_ROOT=""
FULLY_QUALIFIED=false
NOTARIZATION_VERIFIED=false

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-clean-install-qualification.sh --archive <preview.tar.gz> [--receipt <path>] [--notarization-receipt <path>] [--allow-adhoc] [--allow-unnotarized] [--keep-work]

Runs the Goal 2 Track 1 clean-install qualification against a packaged macOS preview archive.
The harness uses a fresh HOME, minimal PATH, temporary install prefix, empty VM state directory,
and installed wrapper only. It requires Developer ID signatures plus an Accepted notarization
receipt bound to the archive, CLI, and helper. It does not require or claim nested VM detonation.
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
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
    --receipt)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      RECEIPT_PATH=$2
      shift 2
      ;;
    --receipt=*)
      RECEIPT_PATH=${1#--receipt=}
      shift
      ;;
    --notarization-receipt)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      NOTARIZATION_RECEIPT=$2
      shift 2
      ;;
    --notarization-receipt=*)
      NOTARIZATION_RECEIPT=${1#--notarization-receipt=}
      shift
      ;;
    --allow-adhoc)
      ALLOW_ADHOC=true
      shift
      ;;
    --allow-unnotarized|--skip-spctl)
      ALLOW_UNNOTARIZED=true
      shift
      ;;
    --keep-work)
      KEEP_WORK=true
      shift
      ;;
    --help|-h)
      usage
      ;;
    *)
      if [ -z "$ARCHIVE" ]; then
        ARCHIVE=$1
        shift
      else
        usage
      fi
      ;;
  esac
done

cleanup() {
  if [ "$KEEP_WORK" != "true" ] && [ -n "$WORK_ROOT" ]; then
    rm -rf "$WORK_ROOT"
  elif [ -n "$WORK_ROOT" ]; then
    echo "qualification_work_root=$WORK_ROOT"
  fi
}
trap cleanup EXIT HUP INT TERM

fail() {
  echo "qualification_failed=$1" >&2
  exit 1
}

require_contains() {
  PATTERN=$1
  FILE=$2
  REASON=$3
  if ! grep -q "$PATTERN" "$FILE"; then
    fail "$REASON"
  fi
}

require_fixed_contains() {
  PATTERN=$1
  FILE=$2
  REASON=$3
  if ! grep -F -q "$PATTERN" "$FILE"; then
    fail "$REASON"
  fi
}

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

sha256_file() {
  shasum -a 256 "$1" | awk '{print "sha256:" $1}'
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

codesign_summary() {
  /usr/bin/codesign -dv --verbose=4 "$1" 2>&1 || true
}

codesign_signature_kind() {
  SUMMARY=$(codesign_summary "$1")
  if printf '%s\n' "$SUMMARY" | grep -q 'Signature=adhoc'; then
    echo "adhoc"
  elif printf '%s\n' "$SUMMARY" | grep -q '^Authority=Developer ID Application:'; then
    echo "developer_id_application"
  elif printf '%s\n' "$SUMMARY" | grep -q '^Authority=Apple Development:'; then
    echo "apple_development"
  elif printf '%s\n' "$SUMMARY" | grep -q '^Authority=Apple Distribution:'; then
    echo "apple_distribution"
  else
    echo "signed_unknown"
  fi
}

json_field() {
  /usr/bin/plutil -extract "$1" raw -o - "$2" 2>/dev/null || true
}

run_clean() {
  env -i \
    HOME="$CLEAN_HOME" \
    TMPDIR="$CLEAN_TMP/" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    "$@"
}

require_archive() {
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
  ARCHIVE=$(CDPATH= cd -- "$(dirname -- "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")
  PACKAGE_NAME=$(basename "$ARCHIVE" .tar.gz)
  if [ -z "$RECEIPT_PATH" ]; then
    RECEIPT_PATH="$REPO_ROOT/dist/$PACKAGE_NAME-clean-install-qualification.json"
  fi
  if [ -z "$NOTARIZATION_RECEIPT" ]; then
    NOTARIZATION_RECEIPT=${WHOATHERE_RELEASE_NOTARIZATION_RECEIPT:-${WHOATHERE_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}/bundle/release-notarization.json}
  fi
}

verify_checksum() {
  if [ -f "$ARCHIVE.sha256" ]; then
    shasum -a 256 -c "$ARCHIVE.sha256"
    CHECKSUM_STATUS=verified
  else
    CHECKSUM_STATUS=missing_sidecar
    fail archive_checksum_sidecar_missing
  fi
}

detect_clean_vm_driver() {
  if command -v tart >/dev/null 2>&1; then
    CLEAN_VM_DRIVER="tart_available_not_used"
    CLEAN_VM_GAP="clean macOS VM driver is installed, but this harness does not automate VM creation"
  elif command -v vz >/dev/null 2>&1; then
    CLEAN_VM_DRIVER="vz_available_not_used"
    CLEAN_VM_GAP="clean macOS VM driver is installed, but this harness does not automate VM creation"
  elif command -v orb >/dev/null 2>&1; then
    CLEAN_VM_DRIVER="not_available_orb_linux_only"
    CLEAN_VM_GAP="no autonomous clean macOS VM driver was available; Orb is Linux-oriented and unsuitable for macOS Gatekeeper qualification"
  else
    CLEAN_VM_DRIVER="not_available"
    CLEAN_VM_GAP="no autonomous clean macOS VM driver was available on this host"
  fi
}

extract_archive() {
  tar -xzf "$ARCHIVE" -C "$WORK_ROOT/extract"
  EXTRACTED_ROOT="$WORK_ROOT/extract/$PACKAGE_NAME"
  CLI="$EXTRACTED_ROOT/bin/whoathere"
  INSTALLER="$EXTRACTED_ROOT/install-macos-preview.sh"
  HELPER="$EXTRACTED_ROOT/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  PROVISIONER="$EXTRACTED_ROOT/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh"
  NPM_UV_VALIDATOR="$EXTRACTED_ROOT/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh"

  test -x "$CLI" || fail extracted_cli_missing
  test -x "$INSTALLER" || fail extracted_installer_missing
  test -x "$HELPER" || fail extracted_helper_missing
  test -x "$PROVISIONER" || fail extracted_provisioner_missing
  test -x "$NPM_UV_VALIDATOR" || fail extracted_npm_uv_validator_missing
  sh -n "$INSTALLER"
  sh -n "$PROVISIONER"
  sh -n "$NPM_UV_VALIDATOR"
}

verify_signatures() {
  /usr/bin/codesign --verify --strict --verbose=2 "$CLI" >/dev/null
  /usr/bin/codesign --verify --strict --verbose=2 "$HELPER" >/dev/null
  CLI_SIGNATURE_KIND=$(codesign_signature_kind "$CLI")
  HELPER_SIGNATURE_KIND=$(codesign_signature_kind "$HELPER")

  if [ "$ALLOW_ADHOC" != "true" ]; then
    if [ "$CLI_SIGNATURE_KIND" != "developer_id_application" ]; then
      echo "cli_signature_kind=$CLI_SIGNATURE_KIND" >&2
      fail developer_id_cli_signature_required
    fi
    if [ "$HELPER_SIGNATURE_KIND" != "developer_id_application" ]; then
      echo "helper_signature_kind=$HELPER_SIGNATURE_KIND" >&2
      fail developer_id_helper_signature_required
    fi
  fi
}

verify_notarization_receipt() {
  NOTARIZATION_STATUS=""
  NOTARIZATION_ID=""
  NOTARIZATION_ARCHIVE_DIGEST=""
  NOTARIZATION_CLI_DIGEST=""
  NOTARIZATION_HELPER_DIGEST=""
  NOTARIZATION_CLI_SIGNATURE_KIND=""
  NOTARIZATION_HELPER_SIGNATURE_KIND=""

  if [ "$ALLOW_UNNOTARIZED" = "true" ]; then
    return
  fi
  if [ ! -f "$NOTARIZATION_RECEIPT" ]; then
    echo "notarization_receipt_missing=$NOTARIZATION_RECEIPT" >&2
    fail notarization_receipt_missing
  fi

  NOTARIZATION_SCHEMA=$(json_field schema_version "$NOTARIZATION_RECEIPT")
  NOTARIZATION_ARTIFACT=$(json_field artifact_name "$NOTARIZATION_RECEIPT")
  NOTARIZATION_ARCHIVE_DIGEST=$(json_field archive_sha256 "$NOTARIZATION_RECEIPT")
  NOTARIZATION_CLI_DIGEST=$(json_field cli_sha256 "$NOTARIZATION_RECEIPT")
  NOTARIZATION_HELPER_DIGEST=$(json_field helper_sha256 "$NOTARIZATION_RECEIPT")
  NOTARIZATION_STATUS=$(json_field notarytool_status "$NOTARIZATION_RECEIPT")
  NOTARIZATION_ID=$(json_field notarytool_id "$NOTARIZATION_RECEIPT")
  NOTARIZATION_CLI_SIGNATURE_KIND=$(json_field cli_signature_kind "$NOTARIZATION_RECEIPT")
  NOTARIZATION_HELPER_SIGNATURE_KIND=$(json_field helper_signature_kind "$NOTARIZATION_RECEIPT")

  test "$NOTARIZATION_SCHEMA" = "whoathere.macos_vm.release_notarization.v1" || fail notarization_schema_invalid
  test "$NOTARIZATION_ARTIFACT" = "$PACKAGE_NAME" || fail notarization_artifact_mismatch
  test "$NOTARIZATION_ARCHIVE_DIGEST" = "$(sha256_file "$ARCHIVE")" || fail notarization_archive_digest_mismatch
  test "$NOTARIZATION_CLI_DIGEST" = "$(sha256_file "$CLI")" || fail notarization_cli_digest_mismatch
  test "$NOTARIZATION_HELPER_DIGEST" = "$(sha256_file "$HELPER")" || fail notarization_helper_digest_mismatch
  test "$NOTARIZATION_STATUS" = "Accepted" || fail notarization_status_not_accepted
  test -n "$NOTARIZATION_ID" || fail notarization_id_missing
  test "$NOTARIZATION_CLI_SIGNATURE_KIND" = "developer_id_application" || fail notarization_cli_signature_invalid
  test "$NOTARIZATION_HELPER_SIGNATURE_KIND" = "developer_id_application" || fail notarization_helper_signature_invalid

  NOTARIZATION_VERIFIED=true
}

verify_installed_wrapper() {
  INSTALL_DRY_RUN_OUTPUT="$WORK_ROOT/install-dry-run.txt"
  INSTALL_OUTPUT="$WORK_ROOT/install.txt"
  HELP_OUTPUT="$WORK_ROOT/help.txt"
  DOCTOR_OUTPUT="$WORK_ROOT/doctor.json"
  STATUS_OUTPUT="$WORK_ROOT/vm-status.json"
  PREFLIGHT_OUTPUT="$WORK_ROOT/reprovision-preflight.txt"
  NPM_UV_OUTPUT="$WORK_ROOT/npm-uv-validation.txt"
  SHIM_DRY_RUN_OUTPUT="$WORK_ROOT/shim-dry-run.txt"
  SHIM_INSTALL_OUTPUT="$WORK_ROOT/shim-install.txt"
  DETONATE_OUTPUT="$WORK_ROOT/detonate-dry-run.json"

  run_clean "$INSTALLER" --dry-run --prefix "$INSTALL_PREFIX" > "$INSTALL_DRY_RUN_OUTPUT"
  require_contains 'install_status=dry_run_not_installed' "$INSTALL_DRY_RUN_OUTPUT" installer_dry_run_status_missing
  run_clean "$INSTALLER" --prefix "$INSTALL_PREFIX" > "$INSTALL_OUTPUT"
  require_contains 'install_status=ok' "$INSTALL_OUTPUT" installer_status_missing

  WRAPPER="$INSTALL_PREFIX/bin/whoathere"
  test -x "$WRAPPER" || fail installed_wrapper_missing
  INSTALLED_RELEASE_DIR="$INSTALL_PREFIX/releases/$PACKAGE_NAME"
  INSTALLED_HELPER="$INSTALLED_RELEASE_DIR/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  test -x "$INSTALLED_HELPER" || fail installed_helper_missing
  /usr/bin/codesign --verify --strict --verbose=2 "$INSTALLED_RELEASE_DIR/bin/whoathere" >/dev/null
  /usr/bin/codesign --verify --strict --verbose=2 "$INSTALLED_HELPER" >/dev/null

  run_clean "$WRAPPER" --help > "$HELP_OUTPUT"
  require_contains 'whoathere <doctor' "$HELP_OUTPUT" installed_wrapper_help_missing

  run_clean "$WRAPPER" doctor --json --state-dir "$STATE_DIR" > "$DOCTOR_OUTPUT"
  require_contains '"release_ready": false' "$DOCTOR_OUTPUT" doctor_release_ready_not_false
  require_contains '"high_risk_allowed": false' "$DOCTOR_OUTPUT" doctor_high_risk_not_false
  require_contains '"release_claim": "vm_detonation_with_safe_sync_back_beta"' "$DOCTOR_OUTPUT" doctor_release_claim_missing
  require_contains '"package_acquisition_policy": "local_only_no_public_resolver"' "$DOCTOR_OUTPUT" doctor_package_policy_missing
  require_contains '"sync_validation_receipt_missing"' "$DOCTOR_OUTPUT" doctor_sync_validation_missing_reason_absent
  require_contains '"release_sync_back_validation_not_verified"' "$DOCTOR_OUTPUT" doctor_sync_release_blocker_absent
  require_contains '"guest_reprovision_required": true' "$DOCTOR_OUTPUT" doctor_reprovision_required_absent
  require_contains 'helpers/macos-vm-helper/scripts/provision-guest-readiness.sh' "$DOCTOR_OUTPUT" doctor_reprovision_command_missing
  EXPECTED_INSTALLED_HELPER_CANONICAL=$(cd "$(dirname "$INSTALLED_HELPER")" && pwd -P)/$(basename "$INSTALLED_HELPER")
  require_fixed_contains "$EXPECTED_INSTALLED_HELPER_CANONICAL" "$DOCTOR_OUTPUT" doctor_installed_helper_path_missing

  run_clean "$WRAPPER" vm status --json --state-dir "$STATE_DIR" > "$STATUS_OUTPUT"
  require_contains '"ready": false' "$STATUS_OUTPUT" vm_status_ready_not_false
  require_contains '"runtime_ready": false' "$STATUS_OUTPUT" vm_status_runtime_ready_not_false
  require_contains '"manifest_present": false' "$STATUS_OUTPUT" vm_status_manifest_not_false
  require_contains '"state_dir_exists": false' "$STATUS_OUTPUT" vm_status_state_dir_not_false

  set +e
  run_clean "$WRAPPER" vm reprovision --preflight --state-dir "$STATE_DIR" > "$PREFLIGHT_OUTPUT" 2>&1
  PREFLIGHT_STATUS=$?
  set -e
  test "$PREFLIGHT_STATUS" -eq 64
  require_contains 'status=preflight' "$PREFLIGHT_OUTPUT" reprovision_preflight_status_missing
  require_contains 'disk_image_present=false' "$PREFLIGHT_OUTPUT" reprovision_preflight_disk_missing
  require_contains 'ready_for_sudo_provisioning=false' "$PREFLIGHT_OUTPUT" reprovision_preflight_ready_state_missing

  set +e
  run_clean "$WRAPPER" vm validate-npm-uv --execute --state-dir "$STATE_DIR" > "$NPM_UV_OUTPUT" 2>&1
  NPM_UV_STATUS=$?
  set -e
  test "$NPM_UV_STATUS" -eq 64
  require_contains 'guest_tooling_not_ready_for_npm_uv_validation=true' "$NPM_UV_OUTPUT" npm_uv_stale_tooling_reason_missing
  require_contains 'ready_for_sudo_provisioning=false' "$NPM_UV_OUTPUT" npm_uv_preflight_ready_state_missing
  if grep -q 'whoathere doctor' "$NPM_UV_OUTPUT"; then
    fail stale_tooling_path_dumped_doctor_json
  fi

  run_clean "$WRAPPER" shim install --dry-run --include-python > "$SHIM_DRY_RUN_OUTPUT"
  require_contains 'whoathere shim install' "$SHIM_DRY_RUN_OUTPUT" shim_dry_run_output_missing
  mkdir -p "$SHIM_DIR"
  run_clean "$WRAPPER" shim install --dest "$SHIM_DIR" --include-python > "$SHIM_INSTALL_OUTPUT"
  for shim in npm npx pip pip3 python python3; do
    test -x "$SHIM_DIR/$shim" || fail "shim_${shim}_missing"
  done

  mkdir -p "$NPM_WORKSPACE"
  printf '%s\n' '{"name":"whoathere-clean-install-smoke","version":"0.0.1","dependencies":{}}' > "$NPM_WORKSPACE/package.json"
  run_clean "$WRAPPER" vm detonate --workspace "$NPM_WORKSPACE" --state-dir "$STATE_DIR" --sync-back --json npm -- install > "$DETONATE_OUTPUT"
  require_contains '"sync_back_enabled": true' "$DETONATE_OUTPUT" detonate_sync_back_flag_missing
  require_contains '"verdict": "dry_run_execute_required"' "$DETONATE_OUTPUT" detonate_dry_run_verdict_missing
  require_contains '"sync_back_execute_required_for_guest_evidence"' "$DETONATE_OUTPUT" detonate_sync_evidence_reason_missing
  if [ -e "$NPM_WORKSPACE/node_modules" ]; then
    fail detonate_dry_run_mutated_workspace
  fi

  if grep -F "$REPO_ROOT" "$INSTALL_DRY_RUN_OUTPUT" "$INSTALL_OUTPUT" "$HELP_OUTPUT" "$DOCTOR_OUTPUT" "$STATUS_OUTPUT" "$PREFLIGHT_OUTPUT" "$NPM_UV_OUTPUT" "$SHIM_DRY_RUN_OUTPUT" "$SHIM_INSTALL_OUTPUT" "$DETONATE_OUTPUT" >/dev/null; then
    fail installed_outputs_leaked_repo_path
  fi
}

write_receipt() {
  RECEIPT_DIR=$(dirname "$RECEIPT_PATH")
  mkdir -p "$RECEIPT_DIR"
  RECEIPT_TMP="$RECEIPT_PATH.$$"
  CREATED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  ARCHIVE_DIGEST=$(sha256_file "$ARCHIVE")
  CLI_DIGEST=$(sha256_file "$CLI")
  HELPER_DIGEST=$(sha256_file "$HELPER")
  if [ "$ALLOW_UNNOTARIZED" = "true" ] || [ "$ALLOW_ADHOC" = "true" ] || [ "$NOTARIZATION_VERIFIED" != "true" ]; then
    FULLY_QUALIFIED=false
  else
    FULLY_QUALIFIED=true
  fi
  cat > "$RECEIPT_TMP" <<EOF
{
  "schema_version": "whoathere.macos_clean_install_qualification.v1",
  "qualified": $FULLY_QUALIFIED,
  "partial_clean_room_qualified": true,
  "created_at": "$(json_escape "$CREATED_AT")",
  "artifact_name": "$(json_escape "$PACKAGE_NAME")",
  "archive_path": "$(json_escape "$ARCHIVE")",
  "archive_sha256": "$(json_escape "$ARCHIVE_DIGEST")",
  "checksum_status": "$(json_escape "$CHECKSUM_STATUS")",
  "host_os": "$(json_escape "$(sw_vers -productVersion)")",
  "host_arch": "$(json_escape "$(uname -m)")",
  "clean_vm_driver": "$(json_escape "$CLEAN_VM_DRIVER")",
  "clean_vm_gap": "$(json_escape "$CLEAN_VM_GAP")",
  "fallback_harness": "clean_home_minimal_env_user_prefix",
  "nested_vm_detonation_required": false,
  "cli_sha256": "$(json_escape "$CLI_DIGEST")",
  "helper_sha256": "$(json_escape "$HELPER_DIGEST")",
  "cli_signature_kind": "$(json_escape "$CLI_SIGNATURE_KIND")",
  "helper_signature_kind": "$(json_escape "$HELPER_SIGNATURE_KIND")",
  "developer_id_required": true,
  "developer_id_requirement_bypassed": $ALLOW_ADHOC,
  "notarization_required": true,
  "notarization_requirement_bypassed": $ALLOW_UNNOTARIZED,
  "notarization_receipt_path": "$(json_escape "$NOTARIZATION_RECEIPT")",
  "notarization_verified": $NOTARIZATION_VERIFIED,
  "notarytool_status": "$(json_escape "$NOTARIZATION_STATUS")",
  "notarytool_id": "$(json_escape "$NOTARIZATION_ID")",
  "spctl_execute_not_applicable_for_bare_cli": true,
  "spctl_container_not_applicable_for_tar_gz_or_unstapled_zip": true,
  "gatekeeper_distribution_qualified": $FULLY_QUALIFIED,
  "installed_prefix_shape": "user_level_prefix_with_wrapper_helper_env",
  "clean_home_used": true,
  "minimal_path_used": true,
  "dev_repo_path_absent_from_installed_outputs": true,
  "doctor_fail_closed_without_vm_state": true,
  "vm_status_fail_closed_without_vm_state": true,
  "reprovision_preflight_fail_closed_without_disk": true,
  "npm_uv_validation_fail_closed_without_guest_tooling": true,
  "shim_install_verified": true,
  "sync_back_dry_run_verified": true,
  "full_vm_backed_detonation_covered": false,
  "full_vm_backed_detonation_gap": "Goal 2 Track 1 intentionally validates clean install behavior only; full VM-backed detonation remains same-host runtime qualification."
}
EOF
  mv "$RECEIPT_TMP" "$RECEIPT_PATH"
}

require_host
require_archive
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-clean-install.XXXXXX")
mkdir -p "$WORK_ROOT/extract"
CLEAN_HOME="$WORK_ROOT/clean home"
CLEAN_TMP="$WORK_ROOT/tmp"
INSTALL_PREFIX="$CLEAN_HOME/.whoathere prefix's"
STATE_DIR="$CLEAN_HOME/vm-state"
SHIM_DIR="$CLEAN_HOME/shims"
NPM_WORKSPACE="$CLEAN_HOME/npm workspace"
mkdir -p "$CLEAN_HOME" "$CLEAN_TMP"

verify_checksum
detect_clean_vm_driver
extract_archive
verify_signatures
verify_notarization_receipt
verify_installed_wrapper
write_receipt

echo "clean_install_harness_passed=true"
echo "clean_install_partial_qualification_passed=true"
echo "clean_install_fully_qualified=$FULLY_QUALIFIED"
echo "qualification_receipt=$RECEIPT_PATH"
echo "clean_vm_driver=$CLEAN_VM_DRIVER"
echo "fallback_harness=clean_home_minimal_env_user_prefix"
