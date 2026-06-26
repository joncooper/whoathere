# macOS VM Goal 1 Checkpoint

Status: in progress.

Goal 1 is the Apple Silicon macOS VM lifecycle foundation. It does not enable npm, pip, uv,
detonation, or sync-back execution.

## Implemented

- Added `whoathere/helpers/macos-vm-helper`, a Swift Package Manager helper that imports Apple `Virtualization.framework`.
- Helper commands: `version`, `status`, `init`, `start`, `suspend`, `reset`, `prune`, and `health`.
- Helper JSON contract includes schema version, helper version, host support, Virtualization.framework linkage, bundle paths, reason codes, and exit code.
- Helper `init --execute --image <path>` creates a managed disk-import bundle from an explicit local disk image, copies the disk to `bundle/disk.img`, writes `bundle/config.json`, and writes `bundle/image.manifest`.
- Disk-import bundles remain non-bootable and non-ready until auxiliary storage, hardware model, machine identifier metadata, and real signature verification are present.
- Helper `init --execute --restore-image <path>` now has a local IPSW install path using `VZMacOSRestoreImage`, `VZMacOSInstaller`, raw disk creation, `VZMacAuxiliaryStorage`, hardware-model persistence, and machine-identifier persistence.
- Restore-image bundles still remain non-ready until signature verification, persistent runtime supervision, and health proof are implemented.
- Helper `start --execute` now has a persistent runtime-process scaffold that launches internal `run`, starts the VM through `VZVirtualMachine.start`, and writes host-runtime state plus health proof when start succeeds.
- Helper `health` reports host-runtime health proof only; it does not prove guest readiness.
- Added a helper entitlement plist and local signing script for `com.apple.security.virtualization`.
- Helper `status` reports missing bundle/config/manifest/disk/auxiliary storage/hardware model/machine identifier/signature proof independently.
- Helper `start` and `health` fail closed until the VM has real Virtualization metadata, signature verification, persistent runtime management, and guest readiness proof.
- Rust CLI accepts `--helper <path>` or `WHOATHERE_MACOS_VM_HELPER` for VM and doctor commands.
- Rust CLI delegates helper-backed `vm status`, `vm init --execute`, and lifecycle actions while preserving dry-run behavior.
- Rust CLI helper execution now requires an absolute canonical helper path, clears the inherited environment, bounds stdout/stderr, and enforces operation timeouts.
- `protect uv -- sync` and other high-risk workflows remain fail-closed.

## Bundle Layout

Default state directory:

```text
~/.whoathere/macos-vm
```

Managed files and directories:

```text
bundle/config.json
bundle/image.manifest
bundle/disk.img
bundle/auxiliary-storage
bundle/hardware-model.bin
bundle/machine-identifier.bin
bundle/runtime.json
bundle/health.json
bundle/runtime.pid
bundle/saved-state.bin
logs/
runs/
cache/
reports/
overlays/
```

## Current Blockers

- Restore-image installation is implemented as a local IPSW path, but still needs real-host validation with a signed, entitled helper and release fixture.
- Full signature/notarization verification is not implemented yet.
- Persistent VM process management is scaffolded, but needs real-host validation, graceful guest stop, and saved-state suspend/resume semantics.
- Guest readiness proof is not implemented yet; current health proof is host-runtime start only.
- A real bootable bundle requires auxiliary storage, hardware model, and machine identifier metadata; a disk image alone is not enough.
- No package-manager command is allowed to execute from this work.

## Local Smoke

Build and test helper:

```sh
cd /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper
swift test
```

Wire helper into Rust CLI:

```sh
export WHOATHERE_MACOS_VM_HELPER=/Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/debug/whoathere-macos-vm-helper
cargo run --manifest-path /Users/jdc/src/whoathere/whoathere/Cargo.toml -p whoathere-cli -- vm status --json
```

Expected today: helper is available, high-risk execution is disabled, and lifecycle readiness
fails closed with precise missing-bundle or missing-metadata reason codes.
