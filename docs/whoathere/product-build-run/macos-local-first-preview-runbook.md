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
- uv remains fail-closed until uv is provisioned into the validation VM and live fixture/project
  checks pass.
- Sync-back remains disabled. The current posture is detonation/admission evidence only.

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
- `macos_vm_manifest_signature_not_verified`
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
  scanner availability, npm/uv proof, and public package policy gates are actually complete.

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
