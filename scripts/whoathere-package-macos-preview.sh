#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUST_WORKSPACE="$REPO_ROOT/whoathere"
HELPER_ROOT="$RUST_WORKSPACE/helpers/macos-vm-helper"
DIST_DIR=${WHOATHERE_DIST_DIR:-"$REPO_ROOT/dist"}
SIGN_IDENTITY=${WHOATHERE_CODESIGN_IDENTITY:--}
SKIP_VALIDATION=${WHOATHERE_PACKAGE_SKIP_VALIDATION:-false}
ALLOW_SKIPPED_VALIDATION=${WHOATHERE_PACKAGE_ALLOW_SKIPPED_VALIDATION:-false}
ALLOW_DIRTY_PACKAGE=${WHOATHERE_PACKAGE_ALLOW_DIRTY:-false}
VERSION=${WHOATHERE_PREVIEW_VERSION:-$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%d%H%M%S)}
PACKAGE_NAME="whoathere-macos-arm64-preview-$VERSION"
STAGE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-package.XXXXXX")
PACKAGE_ROOT="$STAGE_ROOT/$PACKAGE_NAME"
CLI_BIN="$RUST_WORKSPACE/target/release/whoathere"
HELPER_BIN="$HELPER_ROOT/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
ARCHIVE_PATH="$DIST_DIR/$PACKAGE_NAME.tar.gz"
CHECKSUM_PATH="$ARCHIVE_PATH.sha256"
SMOKE_ROOT=""

cleanup() {
  rm -rf "$STAGE_ROOT"
  if [ -n "$SMOKE_ROOT" ]; then
    rm -rf "$SMOKE_ROOT"
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

require_release_integrity() {
  if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    GIT_HEAD=$(git -C "$REPO_ROOT" rev-parse --short HEAD)
    if [ -z "${WHOATHERE_PREVIEW_VERSION:-}" ] && [ "$VERSION" != "$GIT_HEAD" ]; then
      echo "package_version_head_mismatch=true" >&2
      echo "package_version=$VERSION" >&2
      echo "git_head=$GIT_HEAD" >&2
      exit 65
    fi
    if [ "$ALLOW_DIRTY_PACKAGE" != "true" ]; then
      GIT_STATUS=$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal)
      if [ -n "$GIT_STATUS" ]; then
        echo "package_worktree_dirty=true" >&2
        printf '%s\n' "$GIT_STATUS" >&2
        echo "set WHOATHERE_PACKAGE_ALLOW_DIRTY=true only for non-release developer experiments" >&2
        exit 65
      fi
    fi
  fi
  if [ "$SKIP_VALIDATION" = "true" ] && [ "$ALLOW_SKIPPED_VALIDATION" != "true" ]; then
    echo "package_validation_skip_refused=true" >&2
    echo "set WHOATHERE_PACKAGE_ALLOW_SKIPPED_VALIDATION=true only after equivalent validation has already passed" >&2
    exit 65
  fi
}

run_validation() {
  if [ "$SKIP_VALIDATION" = "true" ]; then
    echo "validation_skipped=true"
    return
  fi

  cargo fmt --manifest-path "$RUST_WORKSPACE/Cargo.toml" --all -- --check
  cargo test --manifest-path "$RUST_WORKSPACE/Cargo.toml"
  cargo clippy --manifest-path "$RUST_WORKSPACE/Cargo.toml" --all-targets -- -D warnings
}

build_artifacts() {
  cargo build --release --manifest-path "$RUST_WORKSPACE/Cargo.toml" -p whoathere-cli --bin whoathere
  /usr/bin/codesign --force --options runtime --sign "$SIGN_IDENTITY" "$CLI_BIN"
  /usr/bin/codesign --verify --strict --verbose=2 "$CLI_BIN"

  SWIFT_CACHE_ROOT=${WHOATHERE_SWIFT_CACHE_DIR:-"$REPO_ROOT/.build/swiftpm-cache"}
  SWIFT_MODULE_CACHE="$SWIFT_CACHE_ROOT/clang-module-cache"
  mkdir -p "$SWIFT_MODULE_CACHE"
  export CLANG_MODULE_CACHE_PATH="$SWIFT_MODULE_CACHE"

  (
    cd "$HELPER_ROOT"
    swift test --disable-sandbox -Xcc -fmodules-cache-path="$SWIFT_MODULE_CACHE"
    swift build -c release --disable-sandbox -Xcc -fmodules-cache-path="$SWIFT_MODULE_CACHE"
    ./scripts/sign-local-helper.sh "$HELPER_BIN"
  )
}

run_release_gate() {
  "$CLI_BIN" vm red-team-gate --json >/dev/null
}

stage_package() {
  rm -f "$ARCHIVE_PATH" "$CHECKSUM_PATH"
  mkdir -p \
    "$PACKAGE_ROOT/bin" \
    "$PACKAGE_ROOT/docs" \
    "$PACKAGE_ROOT/helpers/macos-vm-helper/.build/arm64-apple-macosx/release" \
    "$PACKAGE_ROOT/helpers/macos-vm-helper/guest-agent" \
    "$PACKAGE_ROOT/helpers/macos-vm-helper/scripts"

  install -m 0755 "$CLI_BIN" "$PACKAGE_ROOT/bin/whoathere"
  install -m 0755 "$REPO_ROOT/scripts/whoathere-install-macos-preview.sh" "$PACKAGE_ROOT/install-macos-preview.sh"
  install -m 0755 "$HELPER_BIN" "$PACKAGE_ROOT/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  install -m 0644 "$HELPER_ROOT/whoathere-macos-vm-helper.entitlements" "$PACKAGE_ROOT/helpers/macos-vm-helper/whoathere-macos-vm-helper.entitlements"
  install -m 0644 "$HELPER_ROOT/guest-agent/whoathere-guest-ready.c" "$PACKAGE_ROOT/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c"

  for script in "$HELPER_ROOT"/scripts/*.sh; do
    install -m 0755 "$script" "$PACKAGE_ROOT/helpers/macos-vm-helper/scripts/$(basename "$script")"
  done

  install -m 0644 "$RUST_WORKSPACE/README.md" "$PACKAGE_ROOT/docs/whoathere-implementation-readme.md"
  install -m 0644 "$REPO_ROOT/docs/product-build-run/macos-local-first-preview-runbook.md" "$PACKAGE_ROOT/docs/macos-local-first-preview-runbook.md"
  install -m 0644 "$REPO_ROOT/docs/product-build-run/macos-local-release-readiness.md" "$PACKAGE_ROOT/docs/macos-local-release-readiness.md"

  cat > "$PACKAGE_ROOT/README.preview.md" <<EOF
# WhoaThere macOS Local-First Preview

This is an Apple Silicon macOS-only preview artifact.

Included:

- bin/whoathere
- helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
- helper provisioning and validation scripts
- install-macos-preview.sh user-level installer
- guest readiness agent source
- local-first preview runbook and release-readiness checkpoint

This package is locally code-signed with WHOATHERE_CODESIGN_IDENTITY=${SIGN_IDENTITY}.
Notarization is not performed by this script.
The packaged doctor command is expected to report release_ready=false until a validation VM has a
current release-validation receipt for npm/uv and the artifact has passed Developer ID
notarization.

Use docs/macos-local-first-preview-runbook.md for setup, provisioning, validation, and limitations.
EOF
}

write_archive() {
  mkdir -p "$DIST_DIR"
  (
    cd "$STAGE_ROOT"
    tar -czf "$ARCHIVE_PATH" "$PACKAGE_NAME"
  )
  shasum -a 256 "$ARCHIVE_PATH" > "$CHECKSUM_PATH"
}

smoke_package() {
  SMOKE_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-package-smoke.XXXXXX")
  shasum -a 256 -c "$CHECKSUM_PATH"
  tar -xzf "$ARCHIVE_PATH" -C "$SMOKE_ROOT"

  EXTRACTED_ROOT="$SMOKE_ROOT/$PACKAGE_NAME"
  EXTRACTED_CLI="$EXTRACTED_ROOT/bin/whoathere"
  EXTRACTED_INSTALLER="$EXTRACTED_ROOT/install-macos-preview.sh"
  EXTRACTED_HELPER="$EXTRACTED_ROOT/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  EXTRACTED_NPM_UV_VALIDATOR="$EXTRACTED_ROOT/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh"
  EXTRACTED_PROVISIONER="$EXTRACTED_ROOT/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh"
  EXTRACTED_STATE="$SMOKE_ROOT/state"
  INSTALL_PREFIX="$SMOKE_ROOT/install prefix's"
  INSTALL_DRY_RUN_OUTPUT="$SMOKE_ROOT/install-dry-run.txt"
  INSTALL_OUTPUT="$SMOKE_ROOT/install.txt"
  INSTALLED_DOCTOR_OUTPUT="$SMOKE_ROOT/installed-doctor.json"
  DOCTOR_OUTPUT="$SMOKE_ROOT/doctor.json"
  SCANNERS_OUTPUT="$SMOKE_ROOT/scanners-clean.json"
  PREFLIGHT_OUTPUT="$SMOKE_ROOT/provision-preflight.txt"
  CLI_PREFLIGHT_OUTPUT="$SMOKE_ROOT/cli-provision-preflight.txt"
  CLI_NPM_UV_OUTPUT="$SMOKE_ROOT/cli-npm-uv-validation.txt"

  "$EXTRACTED_CLI" --help >/dev/null
  test -x "$EXTRACTED_INSTALLER"
  test -x "$EXTRACTED_NPM_UV_VALIDATOR"
  test -x "$EXTRACTED_PROVISIONER"
  sh -n "$EXTRACTED_INSTALLER"
  sh -n "$EXTRACTED_NPM_UV_VALIDATOR"
  sh -n "$EXTRACTED_PROVISIONER"
  "$EXTRACTED_INSTALLER" --dry-run --prefix "$INSTALL_PREFIX" > "$INSTALL_DRY_RUN_OUTPUT"
  grep -q 'install_status=dry_run_not_installed' "$INSTALL_DRY_RUN_OUTPUT"
  "$EXTRACTED_INSTALLER" --prefix "$INSTALL_PREFIX" > "$INSTALL_OUTPUT"
  grep -q 'install_status=ok' "$INSTALL_OUTPUT"
  "$INSTALL_PREFIX/bin/whoathere" --help >/dev/null
  "$INSTALL_PREFIX/bin/whoathere" doctor --json --state-dir "$SMOKE_ROOT/installed-state" > "$INSTALLED_DOCTOR_OUTPUT"
  EXPECTED_INSTALLED_HELPER="$INSTALL_PREFIX/releases/$PACKAGE_NAME/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper"
  EXPECTED_INSTALLED_HELPER_CANONICAL=$(cd "$(dirname "$EXPECTED_INSTALLED_HELPER")" && pwd -P)/$(basename "$EXPECTED_INSTALLED_HELPER")
  grep -F -q "$EXPECTED_INSTALLED_HELPER_CANONICAL" "$INSTALLED_DOCTOR_OUTPUT"
  grep -q '"release_ready": false' "$INSTALLED_DOCTOR_OUTPUT"
  set +e
  "$EXTRACTED_PROVISIONER" --preflight "$EXTRACTED_STATE" > "$PREFLIGHT_OUTPUT" 2>&1
  PREFLIGHT_STATUS=$?
  set -e
  test "$PREFLIGHT_STATUS" -eq 64
  grep -q 'guest_readiness_preflight=true' "$PREFLIGHT_OUTPUT"
  grep -q 'disk_image_present=false' "$PREFLIGHT_OUTPUT"
  grep -q 'ready_for_sudo_provisioning=false' "$PREFLIGHT_OUTPUT"
  set +e
  "$EXTRACTED_CLI" vm reprovision --preflight --state-dir "$EXTRACTED_STATE" --helper "$EXTRACTED_HELPER" > "$CLI_PREFLIGHT_OUTPUT" 2>&1
  CLI_PREFLIGHT_STATUS=$?
  set -e
  test "$CLI_PREFLIGHT_STATUS" -eq 64
  grep -q 'whoathere vm reprovision' "$CLI_PREFLIGHT_OUTPUT"
  grep -q 'status=preflight' "$CLI_PREFLIGHT_OUTPUT"
  grep -q 'disk_image_present=false' "$CLI_PREFLIGHT_OUTPUT"
  grep -q 'ready_for_sudo_provisioning=false' "$CLI_PREFLIGHT_OUTPUT"
  set +e
  "$EXTRACTED_CLI" vm validate-npm-uv --execute --state-dir "$EXTRACTED_STATE" --helper "$EXTRACTED_HELPER" > "$CLI_NPM_UV_OUTPUT" 2>&1
  CLI_NPM_UV_STATUS=$?
  set -e
  test "$CLI_NPM_UV_STATUS" -eq 64
  grep -q 'whoathere vm validate-npm-uv' "$CLI_NPM_UV_OUTPUT"
  grep -q 'status=execute' "$CLI_NPM_UV_OUTPUT"
  grep -q 'guest_tooling_not_ready_for_npm_uv_validation=true' "$CLI_NPM_UV_OUTPUT"
  grep -q 'ready_for_sudo_provisioning=false' "$CLI_NPM_UV_OUTPUT"
  grep -q '^script_stdout=$' "$CLI_NPM_UV_OUTPUT"
  if grep -q 'whoathere doctor' "$CLI_NPM_UV_OUTPUT"; then
    echo "packaged npm/uv validation should not dump doctor JSON on stale tooling" >&2
    exit 1
  fi
  /usr/bin/codesign --verify --strict --verbose=2 "$EXTRACTED_CLI" >/dev/null
  /usr/bin/codesign --verify --strict --verbose=2 "$EXTRACTED_HELPER" >/dev/null
  "$EXTRACTED_CLI" doctor --json --state-dir "$EXTRACTED_STATE" --helper "$EXTRACTED_HELPER" > "$DOCTOR_OUTPUT"

  grep -q '"release_ready": false' "$DOCTOR_OUTPUT"
  grep -q '"release_claim": "vm_detonation_with_safe_sync_back_beta"' "$DOCTOR_OUTPUT"
  grep -q '"package_acquisition_policy": "local_only_no_public_resolver"' "$DOCTOR_OUTPUT"
  grep -q '"runtime_shutdown": {' "$DOCTOR_OUTPUT"
  grep -F -q "\"receipt_path\": \"$EXTRACTED_STATE/bundle/shutdown.json\"" "$DOCTOR_OUTPUT"
  grep -q '"receipt_present": false' "$DOCTOR_OUTPUT"
  grep -q '"receipt_acceptable_for_no_sync_preview": false' "$DOCTOR_OUTPUT"
  grep -q '"release_validation": {' "$DOCTOR_OUTPUT"
  grep -q '"sync_validation": {' "$DOCTOR_OUTPUT"
  grep -q '"release_validation_receipt_missing"' "$DOCTOR_OUTPUT"
  grep -q '"sync_validation_receipt_missing"' "$DOCTOR_OUTPUT"
  grep -q '"release_sync_back_validation_not_verified"' "$DOCTOR_OUTPUT"
  grep -q '"release_npm_vm_detonation_not_verified"' "$DOCTOR_OUTPUT"
  grep -q '"release_uv_vm_detonation_not_verified"' "$DOCTOR_OUTPUT"
  grep -q '"guest_reprovision_required": true' "$DOCTOR_OUTPUT"
  grep -q '"guest_reprovision_admin_required": true' "$DOCTOR_OUTPUT"
  grep -q '"guest_reprovision_operator_action": "run_guest_reprovision_command_in_interactive_admin_terminal"' "$DOCTOR_OUTPUT"
  grep -q 'helpers/macos-vm-helper/scripts/provision-guest-readiness.sh' "$DOCTOR_OUTPUT"

  mkdir -p "$SMOKE_ROOT/scanner-home" "$SMOKE_ROOT/tmp"
  env -i HOME="$SMOKE_ROOT/scanner-home" TMPDIR="$SMOKE_ROOT/tmp/" PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    "$EXTRACTED_CLI" scanners list --json > "$SCANNERS_OUTPUT"
  grep -q '"bootstrap_receipt_present": false' "$SCANNERS_OUTPUT"
  grep -q '"bootstrap_receipt_valid": false' "$SCANNERS_OUTPUT"
  grep -q '"scanner_bootstrap_receipt_missing"' "$SCANNERS_OUTPUT"
  grep -q '"scanner_public_package_auto_trust_ready": false' "$SCANNERS_OUTPUT"

  echo "package_smoke_passed=true"
}

require_host
require_release_integrity
run_validation
build_artifacts
run_release_gate
stage_package
write_archive
smoke_package

echo "package_created=$ARCHIVE_PATH"
echo "checksum_created=$CHECKSUM_PATH"
echo "notarization_status=not_performed"
