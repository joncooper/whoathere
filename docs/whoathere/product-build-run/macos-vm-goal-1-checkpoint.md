# macOS VM Goal 1 Checkpoint

Status: in progress. Host VM install/start/health-fail-closed/stop lifecycle has been validated on
Apple Silicon macOS; guest readiness proof inside the VM is not yet validated.

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
- Restore-image installation now requires a 64 GiB VM disk and fails before invoking Apple's installer if a smaller disk is requested.
- Restore-image bundles still remain non-ready for package execution until signature verification, runtime validation, and guest health proof are complete.
- Helper `start --execute` now has a persistent runtime-process scaffold that launches internal `run`, starts the VM through `VZVirtualMachine.start`, and writes host-runtime state plus health proof when start succeeds.
- Helper `suspend --execute` now signals the runtime process, which requests a guest stop through Virtualization.framework, writes `bundle/shutdown.json`, and fails closed if shutdown proof is missing.
- Runtime configuration now includes a `VZVirtioSocketDevice` listener on port `47078` for guest readiness.
- Added `guest-agent/whoathere-guest-ready.c`, a tiny guest-side agent that answers a one-time `whoathere.guest_ready.v1` challenge over `AF_VSOCK`.
- Helper `health` now fails closed on host-runtime proof alone and only succeeds when a matching guest proof exists for the live runtime session, challenge hash, image digest, protocol, port, and helper version.
- Guest health proof stores sanitized response metadata and challenge hash, not the raw readiness challenge.
- The local validation script can package `bundle/guest-tools.dmg` from the guest-agent source only using the `hdiutil` UFBI whole-device format, but helper auto-attach is disabled by default because real-host validation showed the tested tools-media attachments prevented boot.
- Added `scripts/provision-guest-readiness.sh`, an admin-required offline provisioning path that compiles the guest agent, mounts the stopped VM disk with ownership enabled, installs a root-owned LaunchDaemon, writes `bundle/guest-provisioning.json`, and avoids host home, secrets, workspaces, package-manager state, and sync-back.
- Non-root-owned offline LaunchDaemon provisioning was tested and did not produce a guest proof; root-owned provisioning requires a local `sudo` run outside this Codex session.
- Added a helper entitlement plist and local signing script for `com.apple.security.virtualization`.
- Added a local IPSW validation script that runs build, test, sign, restore-image install or existing-bundle reuse, guest-tools packaging, status, and then stops fail-closed with the exact provisioning command when `bundle/guest-provisioning.json` is missing.
- Helper `status` reports missing bundle/config/manifest/disk/auxiliary storage/hardware model/machine identifier/signature proof and guest provisioning receipt independently.
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
bundle/guest-provisioning.json
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

- Restore-image installation has been validated locally with a signed, entitled helper and Apple's latest supported restore image; repeatable release fixture validation remains.
- Full signature/notarization verification is not implemented yet; status reports `signature_verification_not_implemented` as a fail-closed readiness reason.
- Persistent VM process management and controlled force-stop fallback have been validated locally; saved-state suspend/resume semantics remain deferred.
- Guest readiness proof protocol, proof binding, guest-agent source, and root-owned offline provisioning script are implemented, but the final guest proof still needs a local admin run of `scripts/provision-guest-readiness.sh` followed by VM boot/health validation.
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

Provision the guest readiness daemon while the VM is stopped:

```sh
sudo /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh /Users/jdc/.whoathere/macos-vm-validation
```

After provisioning, rerun the validation script or start the VM and run `vm health`. Until the
guest daemon response is present and bound to the current runtime session, challenge hash, image
digest, protocol, port, and helper version, `vm health` is expected to fail closed.
