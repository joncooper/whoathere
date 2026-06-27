# WhoaThere macOS Local-First Preview Runbook

## Purpose

This runbook is the operator-facing path for the Apple Silicon macOS local-first preview release.
It is intentionally narrower than the enterprise WhoaThere vision: no Vault dependency, no AWS,
no Windows, no Linux release claim, no public package resolver fallback, and no host sync-back.

The current usable claim is:

- Python local project and local-only requirements detonation can run inside a macOS guest VM.
- Host package-manager execution remains disabled for high-risk workflows.
- Host secrets are not mirrored into the VM.
- npm has a narrow local no-external-dependency project planner, but live npm remains fail-closed
  until Node/npm are provisioned into the validation VM and live fixture/project checks pass.
- uv has a narrow local `uv pip install` project planner, but live uv remains fail-closed until uv
  is provisioned into the validation VM and live fixture/project checks pass. `uv sync` remains
  deferred until lock/source policy is explicit.
- Sync-back remains disabled. The current posture is detonation/admission evidence only.
- Package acquisition is local-only for this preview: `doctor` reports
  `package_acquisition_policy=local_only_no_public_resolver`. Public npm/PyPI resolution remains
  fail-closed unless a separate VM-only resolver policy is implemented and tested.

## Prerequisites

- Apple Silicon macOS host.
- Xcode command line tools.
- Rust toolchain.
- Swift Package Manager.
- At least 64 GiB disk space for the VM bundle and cache.
- 6 GiB RAM available for normal VM validation; 8 GiB is preferred for native/deep tests.
- A macOS restore IPSW, or explicit approval to fetch Apple's latest supported restore image.
- Interactive `sudo` for one stopped-VM guest provisioning step.

Optional, for npm and uv validation:

- A host Node/npm runtime that can be copied into the VM.
- A host uv binary that can be copied into the VM.

The current validation host paths are:

```sh
export WHOATHERE_NODE_RUNTIME_DIR=/Users/jdc/.nvm/versions/node/v22.22.3
export WHOATHERE_UV_BINARY=/Users/jdc/.local/bin/uv
```

## Build

From the repo root:

```sh
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli --bin whoathere
```

Build and sign the macOS VM helper:

```sh
cd /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper
swift test
swift build
./scripts/sign-local-helper.sh
```

Run `./scripts/sign-local-helper.sh` after every `swift build`; SwiftPM replaces the signed helper
binary.

Useful shell variables:

```sh
export WHOATHERE=/Users/jdc/src/whoathere/whoathere/target/debug/whoathere
export WHOATHERE_STATE=/Users/jdc/.whoathere/macos-vm-validation
export WHOATHERE_HELPER=/Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
```

## Package A Preview Artifact

To build a repeatable Apple Silicon preview tarball with the release CLI, signed release helper,
helper scripts, guest readiness agent source, and local preview docs:

```sh
scripts/whoathere-package-macos-preview.sh
```

The script runs Rust validation, builds the release CLI, locally signs the CLI, runs Swift helper
tests, builds and signs the release helper, runs the local red-team fixture gate, writes the
archive and checksum, then extracts the archive and smoke-tests the packaged CLI/helper. The smoke
verifies the checksum, `bin/whoathere --help`, packaged codesign state, and packaged
`doctor --json` fail-closed output with a package-local guest reprovision command.

```text
dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz
dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz.sha256
```

Set `WHOATHERE_CODESIGN_IDENTITY` to use a non-ad-hoc signing identity. The script does not perform
Apple notarization, so final release signing/notarization remains a separate blocker.

## Initialize Or Reuse The VM

Fetch and install Apple's latest supported restore image:

```sh
$WHOATHERE vm init --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --fetch-latest-restore-image --execute
```

Or use a local restore IPSW:

```sh
$WHOATHERE vm init --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --restore-image /absolute/path/to/macos-restore.ipsw --execute
```

Inspect status before starting:

```sh
$WHOATHERE vm status --json --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
$WHOATHERE doctor --json --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

Expected before release hardening is complete:

- `release_ready=false`
- `high_risk_allowed=false`
- Existing validation bundles created before local developer manifest verification may still report
  `macos_vm_manifest_signature_not_verified` until they are reinitialized or explicitly upgraded:

  ```sh
  $WHOATHERE vm upgrade-local-manifest --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
  ```

  The upgrade command only rewrites helper-created local preview manifests from
  `signature_verification_not_implemented` to `local_developer_verified`; malformed, non-local, or
  incomplete bundles remain fail closed. New helper-created preview bundles use
  `signature_status=local_developer_verified` for local lifecycle gating.
- scanner and packaging/red-team release blockers

## Provision Guest Readiness Tooling

The VM must be stopped for provisioning. This step is admin-only because the guest LaunchDaemon and
agent must be root-owned on the guest Data volume.

For Python-only provisioning:

```sh
sudo /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh "$WHOATHERE_STATE"
```

For npm and uv validation, force explicit tool sources:

```sh
sudo WHOATHERE_NODE_RUNTIME_DIR="$WHOATHERE_NODE_RUNTIME_DIR" WHOATHERE_UV_BINARY="$WHOATHERE_UV_BINARY" /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh "$WHOATHERE_STATE"
```

If provisioning is missing or stale, `provision-guest-readiness.sh` and the validation scripts
emit a machine-specific `sudo ... provision-guest-readiness.sh ...` command with detected
`WHOATHERE_NODE_RUNTIME_DIR` and `WHOATHERE_UV_BINARY` values when they are available.
`whoathere doctor --json` also reports `guest_reprovision_command` when it can derive the helper
script path from the configured helper and the guest provisioning receipt is missing or stale.

Then verify the receipt and live guest state:

```sh
$WHOATHERE vm status --json --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
$WHOATHERE vm start --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
sleep 10
$WHOATHERE vm health --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

The receipt should report installed toolchains. The live health proof should report:

```text
guest_toolchain_python3_available=true
guest_toolchain_pip_available=true
guest_toolchain_npm_available=true
guest_toolchain_uv_available=true
high_risk_package_execution_enabled=false
```

If npm or uv is missing from either receipt or health output, keep npm/uv workflows unclaimed and
fail closed.

`whoathere vm detonate --execute` also checks the guest provisioning receipt before preparing a
project payload or invoking the helper. When npm, uv, or the Python/pip staging materials used by
`uv pip install` are missing, the command should fail closed with `helper=null`,
`project_payload=null`, `verdict=preflight_security_outcome`, and the matching toolchain reason code
such as `macos_vm_guest_node_runtime_not_provisioned`,
`macos_vm_guest_uv_binary_not_provisioned`, or `macos_vm_guest_pip_tooling_not_provisioned`.

## Validate Detonation

Run fixture validation:

```sh
WHOATHERE_VM_STATE_DIR="$WHOATHERE_STATE" /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/validate-detonation-fixtures.sh
WHOATHERE_VM_STATE_DIR="$WHOATHERE_STATE" /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
```

Run a local Python project detonation:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json pip -- install .
```

Run local-only requirements detonation:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json pip -- install -r requirements.txt
```

Run a local npm project detonation only for a package with no external dependency resolution:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/npm-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json npm -- install
```

This path is intentionally narrow. `package.json` dependency sections, package specs passed to
`npm install`, public registry overrides, native markers, and lockfiles that imply external
resolution remain fail-closed until a public package acquisition policy exists.

Run a local uv project detonation only through `uv pip install` and only for local/no-public
resolution projects:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json uv -- pip install .
```

`uv sync` is intentionally not a claimed live workflow yet; it remains fail-closed until lockfile
and source policy are explicit and tested.

Unsupported or unsafe inputs must fail before helper execution, including:

- public resolver dependencies
- direct URLs
- VCS/editable dependencies
- native extensions
- binary wheels
- symlink/traversal escapes
- secret files or host credential paths

## Stop And Verify Fail-Closed State

```sh
$WHOATHERE vm suspend --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
$WHOATHERE vm health --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

Final health should fail closed with `runtime_process_not_running`.

## Release Gate

Do not call the macOS local-first preview ready until all of these are true:

- `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` passes.
- `cargo test --manifest-path whoathere/Cargo.toml` passes.
- `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passes.
- Helper `swift test`, `swift build`, and `./scripts/sign-local-helper.sh` pass.
- Guest C compile check passes.
- Shell syntax checks for touched scripts pass.
- ASCII scan over touched docs/scripts/Rust/Swift/C files has no matches.
- `whoathere vm red-team-gate --json` passes with `passed=true`.
- Live VM validation passes for every workflow claimed in the release.
- `doctor --json` still reports `release_ready=false` until packaging, signing/notarization,
  npm/uv proof, and public package policy gates are actually complete.
- Missing scanner binaries are acceptable only while sync-back remains disabled; they must be
  installed or otherwise replaced by explicit evidence before any auto-sync or auto-allow claim.

## Limitations

- This is not a universal malware detector.
- This does not protect arbitrary runtime application behavior after a package is admitted.
- This does not safely execute arbitrary native code.
- This does not sync VM outputs back to the host.
- This does not support global/system Python installs.
- This does not claim npm or uv success until tool provisioning and live detonation pass.
- This does not use public package resolver fallback.
- This does not replace code review for API-compatible packages that add malicious behavior at
  normal runtime call sites.

## Cleanup

Stop the VM before cleanup:

```sh
$WHOATHERE vm suspend --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
```

Prune helper-managed transient state:

```sh
$WHOATHERE vm prune --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
```

Remove the validation VM bundle only when you are sure you no longer need it:

```sh
rm -rf "$WHOATHERE_STATE"
```
