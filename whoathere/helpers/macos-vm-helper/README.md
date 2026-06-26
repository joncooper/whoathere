# WhoaThere macOS VM Helper

This helper is the Apple Silicon macOS lifecycle foundation for the local WhoaThere release.
It is intentionally separate from the Rust CLI and imports Apple `Virtualization.framework`.

Current state:

- Builds on Apple Silicon macOS with Swift Package Manager.
- Reports helper and host readiness as JSON.
- Initializes a managed disk-import bundle from an explicit local disk image.
- Initializes a local restore-image install path from an explicit local macOS IPSW when the helper has the required Apple virtualization entitlement and host support.
- Writes bundle config, disk copy, and image manifest metadata.
- Keeps disk-import bundles non-ready until auxiliary storage, hardware model, machine identifier metadata, and real signature verification exist.
- Keeps high-risk package execution disabled.
- Starts a persistent helper runtime only when disk, auxiliary storage, hardware model, and machine identifier metadata are present.
- Writes host-runtime state and health proof after `VZVirtualMachine.start` succeeds.
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

This performs build, test, sign, restore-image install, status, start, health, suspend, and final
status. It creates a large local VM disk under `~/.whoathere/macos-vm-validation` unless a second
state-directory argument is supplied. Until the guest readiness agent is copied into and run inside
the guest, `health` is expected to fail closed with `guest_health_proof_missing_or_mismatched`.

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
```

The current goal slice supports `--image` disk import and a first `--restore-image` local IPSW
install path. A disk image alone is not a bootable macOS VM bundle. Restore-image installation is
the path that produces the required auxiliary storage, hardware model, and machine identifier
metadata.

Runtime start writes a host-only proof when `VZVirtualMachine.start` returns success. `vm health`
does not treat that as guest readiness. It succeeds only after the guest responds over the
`whoathere.guest_ready.v1` vsock challenge protocol for the current runtime session.

Guest readiness agent:

```sh
cd guest-agent
cc -O2 -Wall -Wextra -o whoathere-guest-ready whoathere-guest-ready.c
```

Build and run that agent inside the macOS guest after the host helper has started the VM. The agent
uses `AF_VSOCK` only; it does not run package managers, import project code, mount host secrets, or
sync files back to the host.

Rust CLI integration:

```sh
export WHOATHERE_MACOS_VM_HELPER=/absolute/path/to/.build/debug/whoathere-macos-vm-helper
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vm status --json
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vm health
```

The Rust CLI launches the helper with a cleared environment, a minimal `PATH`, bounded output,
and operation timeouts. `vm health` is read-only and returns the helper's fail-closed exit code
until the guest vsock proof is present. Helper status and health are diagnostic and never authorize
package execution.

Security boundaries:

- Do not mount the host home directory.
- Do not use host SSH keys.
- Do not pass real npm, PyPI, cloud, Kubernetes, Vault, `.env`, or AI-tool credentials.
- Do not treat helper status as package-execution authorization.
- Package-manager execution and sync-back remain out of scope for this helper slice.
