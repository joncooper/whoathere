# WhoaThere macOS VM Helper

This helper is the Apple Silicon macOS lifecycle foundation for the local WhoaThere release.
It is intentionally separate from the Rust CLI and imports Apple `Virtualization.framework`.

Current state:

- Builds on Apple Silicon macOS with Swift Package Manager.
- Reports helper and host readiness as JSON.
- Initializes a managed disk-import bundle from an explicit local disk image.
- Initializes a local restore-image install path from an explicit local macOS IPSW or an explicit latest-supported restore-image fetch when the helper has the required Apple virtualization entitlement and host support.
- Writes bundle config, disk copy, and image manifest metadata.
- Validates manifest schema, image id, macOS version, arm64/aarch64 architecture, helper version,
  digest fields, and signature status during `status` and lifecycle gating.
- Keeps disk-import bundles non-ready until auxiliary storage, hardware model, machine identifier metadata, and real signature verification exist.
- Keeps high-risk package execution disabled.
- Starts a persistent helper runtime only when disk, auxiliary storage, hardware model, machine identifier metadata, and the guest provisioning receipt are present.
- Writes host-runtime state and health proof after `VZVirtualMachine.start` succeeds.
- Handles runtime `SIGTERM` by requesting a guest stop through Virtualization.framework, falling
  back to VM stop only on timeout or unavailable guest stop, and writing `shutdown.json`.
- Adds a `VZVirtioSocketDevice` guest-readiness listener on port `47078`.
- Includes a tiny guest-side readiness agent source under `guest-agent/`.
- Keeps package execution, sync-back, and real signature verification blocked.

Build and test:

```sh
swift test
```

Local signing for Virtualization.framework:

```sh
swift build
./scripts/sign-local-helper.sh
```

Set `WHOATHERE_CODESIGN_IDENTITY` to a Developer ID or Apple Development signing identity for
non-ad-hoc signing. The default identity is `-` for local ad-hoc development signing.

Real local VM validation with a local IPSW:

```sh
./scripts/validate-local-vm.sh /absolute/path/to/macos-restore.ipsw
```

Or explicitly ask Apple Virtualization.framework for the latest supported restore image and download
it into the WhoaThere state cache before installation:

```sh
./scripts/validate-local-vm.sh --fetch-latest-restore-image
```

This performs build, test, sign, restore-image install, creation of a read-only guest tools DMG,
and status. On rerun, it reuses a complete existing VM bundle instead of reinstalling macOS. If
`bundle/guest-provisioning.json` is missing, it stops fail-closed with the exact
`sudo ./scripts/provision-guest-readiness.sh ...` command to run while the VM is stopped. After
that provisioning receipt exists, rerunning the validation continues through start, health, suspend,
and final status. Health polling defaults to 30 attempts at 10 second intervals and can be adjusted
with `WHOATHERE_VM_HEALTH_ATTEMPTS` and `WHOATHERE_VM_HEALTH_INTERVAL_SECONDS`. It creates a large
local VM disk under `~/.whoathere/macos-vm-validation` unless a second state-directory argument is
supplied. The `--fetch-latest-restore-image` mode also downloads a large IPSW into that state
directory's cache when no complete bundle already exists.

For local resource tuning, set `WHOATHERE_VM_DISK_GIB` or `WHOATHERE_VM_MEMORY_MIB` before running
the validation script. Restore-backed macOS bundles currently use a 64 GiB disk by default, and the
helper rejects smaller restore disks before starting Apple's installer.

Smoke commands:

```sh
.build/debug/whoathere-macos-vm-helper version
.build/debug/whoathere-macos-vm-helper status --state-dir /tmp/whoathere-vm --json
.build/debug/whoathere-macos-vm-helper init --state-dir /tmp/whoathere-vm --execute
```

The `init --execute` command requires one of:

```sh
--image <installed-macos-disk.img>
--restore-image <macos-restore.ipsw>
--fetch-latest-restore-image
```

The current goal slice supports `--image` disk import and a first `--restore-image` local IPSW
install path. It can also explicitly fetch Apple's latest supported restore image, cache it locally,
hash it, and then use the same restore-image install path. A disk image alone is not a bootable
macOS VM bundle. Restore-image installation is the path that produces the required auxiliary
storage, hardware model, and machine identifier metadata.

Runtime start writes a host-only proof when `VZVirtualMachine.start` returns success. `vm health`
does not treat that as guest readiness. It succeeds only after the guest responds over the
`whoathere.guest_ready.v1` vsock challenge protocol for the current runtime session.

`suspend --execute` currently means controlled stop, not saved-state suspend. It signals the
long-running runtime process, which first calls `requestStop()` on the VM. If the guest does not
stop in time, the runtime attempts `stop()` and reports the forced fallback. Saved-state
suspend/resume remains deferred.

Guest readiness agent source:

```sh
cd guest-agent
cc -O2 -Wall -Wextra -o whoathere-guest-ready whoathere-guest-ready.c
```

The agent uses `AF_VSOCK` only; it does not run package managers, import project code, mount host
secrets, or sync files back to the host.
The host stores only sanitized readiness evidence: session id, image digest, helper version,
protocol, port, and challenge hash. It does not persist the raw readiness challenge.
The validation script packages this source into `bundle/guest-tools.dmg` using the `hdiutil` UFBI
whole-device format. The helper does not auto-attach this image unless
`guest_tools_attach_enabled=true` is set in `bundle/config.json`; the current validated boot path
keeps it disabled because Virtualization.framework rejected the tested tools-media attachments.
This shares only the guest-agent source, not the host home directory or project workspace.

Offline guest readiness provisioning:

```sh
sudo ./scripts/provision-guest-readiness.sh /absolute/path/to/vm-state-dir
```

The provisioning script is intentionally admin-only because macOS launchd requires a root-owned
`/Library/LaunchDaemons` plist and root-owned program on the guest Data volume. It attaches the
stopped VM disk with ownership enabled, installs only the `whoathere-guest-ready` binary and
`com.whoathere.guest-ready.plist`, writes `bundle/guest-provisioning.json`, and detaches the disk.
It does not mount host home, SSH keys, project workspaces, real credentials, or package-manager
state. A non-root-owned daemon was tested and did not produce a guest proof.

Rust CLI integration:

```sh
export WHOATHERE_MACOS_VM_HELPER=/absolute/path/to/.build/debug/whoathere-macos-vm-helper
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vm status --json
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vm health
```

The Rust CLI launches the helper with a cleared environment, a minimal `PATH`, bounded output,
and operation timeouts. `vm health` is read-only and returns the helper's fail-closed exit code
until the guest vsock proof matches the current live runtime session, challenge hash, image digest,
protocol, port, and helper version. Helper status and health are diagnostic and never authorize
package execution.

Security boundaries:

- Do not mount the host home directory.
- Do not use host SSH keys.
- Do not pass real npm, PyPI, cloud, Kubernetes, Vault, `.env`, or AI-tool credentials.
- Do not treat helper status as package-execution authorization.
- Package-manager execution and sync-back remain out of scope for this helper slice.
