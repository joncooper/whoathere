# macOS VM Goal 1 Checkpoint

Status: in progress.

Goal 1 is the Apple Silicon macOS VM lifecycle foundation. It does not enable npm, pip, uv,
detonation, or sync-back execution.

## Implemented

- Added `whoathere/helpers/macos-vm-helper`, a Swift Package Manager helper that imports Apple `Virtualization.framework`.
- Helper commands: `version`, `status`, `init`, `start`, `suspend`, `reset`, `prune`, and `health`.
- Helper JSON contract includes schema version, helper version, host support, Virtualization.framework linkage, bundle paths, reason codes, and exit code.
- Helper status validates manifest schema, image id, macOS version, arm64/aarch64 architecture, helper version, digest fields, and signature status without rehashing large VM disks on every status call.
- Helper `init --execute --image <path>` creates a managed disk-import bundle from an explicit local disk image, copies the disk to `bundle/disk.img`, writes `bundle/config.json`, and writes `bundle/image.manifest`.
- Disk-import bundles remain non-bootable and non-ready until auxiliary storage, hardware model, machine identifier metadata, and real signature verification are present.
- Helper `init --execute --restore-image <path>` now has a local IPSW install path using `VZMacOSRestoreImage`, `VZMacOSInstaller`, raw disk creation, `VZMacAuxiliaryStorage`, hardware-model persistence, and machine-identifier persistence.
- Helper `init --execute --fetch-latest-restore-image` explicitly asks Apple Virtualization.framework for the latest supported restore image, downloads it into the WhoaThere state cache, hashes it locally, and then uses the same restore-image install path.
- Restore-image bundles still remain non-ready for package execution until signature verification, runtime validation, and guest health proof are complete.
- Helper `start --execute` now has a persistent runtime-process scaffold that launches internal `run`, starts the VM through `VZVirtualMachine.start`, and writes host-runtime state plus health proof when start succeeds.
- Helper `suspend --execute` now signals the runtime process, which requests a guest stop through Virtualization.framework, writes `bundle/shutdown.json`, and fails closed if shutdown proof is missing.
- Runtime configuration now includes a `VZVirtioSocketDevice` listener on port `47078` for guest readiness.
- Added `guest-agent/whoathere-guest-ready.c`, a tiny guest-side agent that answers a one-time `whoathere.guest_ready.v1` challenge over `AF_VSOCK`.
- Helper `health` now fails closed on host-runtime proof alone and only succeeds when a matching guest proof exists for the live runtime session, challenge hash, image digest, protocol, port, and helper version.
- Guest health proof stores sanitized response metadata and challenge hash, not the raw readiness challenge.
- Helper startup attaches `bundle/guest-tools.dmg` as an optional read-only USB mass-storage device when present; the local validation script creates that image from the guest-agent source only.
- Added a helper entitlement plist and local signing script for `com.apple.security.virtualization`.
- Added a local IPSW validation script that runs build, test, sign, restore-image install, status, start, fail-closed-or-proven health, suspend, and final status.
- Helper `status` reports missing bundle/config/manifest/disk/auxiliary storage/hardware model/machine identifier/signature proof independently.
- Helper `start` and `health` fail closed until the VM has real Virtualization metadata, signature verification, persistent runtime management, and guest readiness proof.
- Rust CLI accepts `--helper <path>` or `WHOATHERE_MACOS_VM_HELPER` for VM and doctor commands.
- Rust CLI delegates helper-backed `vm status`, `vm init --execute`, and lifecycle actions while preserving dry-run behavior.
- Rust CLI delegates read-only `vm health` to the helper and preserves the helper's fail-closed exit code when guest proof is missing.
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
bundle/guest-health.json
bundle/guest-tools.dmg
bundle/shutdown.json
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
- Full signature/notarization verification is not implemented yet; status reports `signature_verification_not_implemented` as a fail-closed readiness reason.
- Persistent VM process management and controlled stop are implemented, but need real-host validation; saved-state suspend/resume semantics remain deferred.
- Guest readiness proof protocol, proof binding, and guest-agent source are implemented, but still need real-host validation inside a booted guest and a provisioning/copy path.
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
cargo run --manifest-path /Users/jdc/src/whoathere/whoathere/Cargo.toml -p whoathere-cli -- vm health
```

Expected today: helper is available, high-risk execution is disabled, and lifecycle readiness
fails closed with precise missing-bundle or missing-metadata reason codes.

Compile the guest readiness agent source:

```sh
cc -Wall -Wextra -c /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c -o /tmp/whoathere-guest-ready.o
```

Real local VM validation requires either a local macOS restore IPSW or an explicit latest-image fetch:

```sh
cd /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper
./scripts/validate-local-vm.sh /absolute/path/to/macos-restore.ipsw
./scripts/validate-local-vm.sh --fetch-latest-restore-image
```

After the VM is running, copy `guest-agent/whoathere-guest-ready.c` into the guest, build it there,
and run it to produce `bundle/guest-health.json`. Until that guest response is present and bound to
the current runtime session, challenge hash, image digest, protocol, port, and helper version,
`vm health` is expected to fail closed.
