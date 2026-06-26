# WhoaThere macOS VM Helper

This helper is the Apple Silicon macOS lifecycle foundation for the local WhoaThere release.
It is intentionally separate from the Rust CLI and imports Apple `Virtualization.framework`.

Current state:

- Builds on Apple Silicon macOS with Swift Package Manager.
- Reports helper and host readiness as JSON.
- Initializes a managed VM bundle from an explicit local installed disk image.
- Writes bundle config, disk copy, and image manifest metadata.
- Keeps high-risk package execution disabled.
- Fails closed for start and health until Virtualization metadata, signature verification, and persistent VM runtime are implemented.

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

The current goal slice supports `--image` bundle import. Restore-image installation is a planned
next step and currently returns `restore_image_install_path_not_implemented`.

Rust CLI integration:

```sh
export WHOATHERE_MACOS_VM_HELPER=/absolute/path/to/.build/debug/whoathere-macos-vm-helper
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vm status --json
```

Security boundaries:

- Do not mount the host home directory.
- Do not use host SSH keys.
- Do not pass real npm, PyPI, cloud, Kubernetes, Vault, `.env`, or AI-tool credentials.
- Do not treat helper status as package-execution authorization.
- Package-manager execution and sync-back remain out of scope for this helper slice.
