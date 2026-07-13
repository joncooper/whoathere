# WhoaThere Linux VZ Package Runtime

This directory builds the separately measured Linux/arm64 package runtime that will eventually be
composed with the qualified Linux VZ telemetry backend. It is not a detonation harness and must
not receive unknown or malicious packages.

The current candidate pins:

- Alpine Linux 3.24.1 aarch64 minirootfs;
- Node.js 24.17.0 and npm 11.12.1;
- Python 3.14.5 and pip 26.1.2;
- the complete exact APK closure and offline image-build tools;
- a repository-owned static aarch64 runtime probe; and
- the exact arm64 Alpine 3.24.1 container image used only as an offline build environment.

`config/runtime-inputs.lock` is the authority for every downloaded byte. Acquisition is a separate
step from construction. The builder accepts only a complete hash-matching input directory, runs the
pinned container with `--network none`, and emits a canonical rootfs archive, a fixed-identity raw
ext2 image, the static probe, and a canonical manifest. The verifier independently extracts both
the archive and ext2 image and compares their canonicalized contents before running only fixed
version and non-execution probes.

Acquire the public, pinned inputs into a new gitignored directory:

```sh
scripts/fetch-pinned-runtime-inputs.sh \
  /absolute/path/to/.whoathere/linux-vz-package-runtime-inputs
```

Build into a new directory. The exact Alpine container image must already be present locally; the
builder never pulls it:

```sh
scripts/build-pinned-runtime-rootfs.sh \
  /absolute/path/to/.whoathere/linux-vz-package-runtime-inputs \
  /absolute/path/to/.whoathere/linux-vz-package-runtime-build
```

Independently verify the result:

```sh
scripts/verify-pinned-runtime-rootfs.sh \
  /absolute/path/to/.whoathere/linux-vz-package-runtime-inputs \
  /absolute/path/to/.whoathere/linux-vz-package-runtime-build
```

The macOS helper also contains an independent Swift decoder and locked-file verifier. It binds the
rootfs, manifest, and runner to externally supplied identities, creates a unique writable APFS
clone, rehashes that clone through its held directory descriptor, and destroys it before returning:

```sh
swift run --package-path ../macos-vm-helper \
  whoathere-linux-vz-package-runtime-identity-verify \
  --runtime-directory /absolute/path/to/.whoathere/linux-vz-package-runtime-build \
  --expected-rootfs-sha256 sha256:... \
  --expected-rootfs-byte-length 1073741824 \
  --expected-runtime-manifest-sha256 sha256:... \
  --expected-package-runner-sha256 sha256:...
```

That verifier exercises only the pre-boot clone lifecycle. It does not attach the clone to a VM,
qualify the runtime, issue execution authority, or run a package.

The current probe supports only `--runtime-probe` and the protected sensor's closed
`fork_exec_exit` alias. Both return the same fixed response saying `package_execution:false`,
`execution_authority:false`, and `sync_back:false`; every other invocation fails with exit 64.
Replacing it with an execution-capable runner will change the rootfs and manifest identities and
requires a new runtime qualification. No request, manifest, or successful probe in this directory
grants package execution.

The rootfs is a distinct runtime composition, not part of the already-qualified diskless telemetry
backend. Adding a storage device, init integration, or runner changes the measured VM configuration;
those changes must pass a separate inert runtime-qualification gate before a one-use execution
grant can exist.
