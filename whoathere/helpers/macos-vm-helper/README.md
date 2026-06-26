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
- Keeps guest readiness, package execution, sync-back, and real signature verification blocked.

Build and test:

```sh
swift test
```

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
metadata. Runtime health proof is host-only: it means `VZVirtualMachine.start` returned success,
not that the guest OS is provisioned, reachable, or safe for package execution.

Rust CLI integration:

```sh
export WHOATHERE_MACOS_VM_HELPER=/absolute/path/to/.build/debug/whoathere-macos-vm-helper
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vm status --json
```

The Rust CLI launches the helper with a cleared environment, a minimal `PATH`, bounded output,
and operation timeouts. Helper status is diagnostic and never authorizes package execution.

Security boundaries:

- Do not mount the host home directory.
- Do not use host SSH keys.
- Do not pass real npm, PyPI, cloud, Kubernetes, Vault, `.env`, or AI-tool credentials.
- Do not treat helper status as package-execution authorization.
- Package-manager execution and sync-back remain out of scope for this helper slice.
