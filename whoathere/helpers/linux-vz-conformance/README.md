# WhoaThere Linux VZ Conformance Harness

This directory contains only trusted inert Linux-on-Mac qualification fixtures. It must not receive
package artifacts or malware.

The first boot input is Alpine Linux 3.24.1's official aarch64 virtual ISO, pinned by SHA-256. The
builder extracts the virt kernel, initramfs, config, and System.map, extracts and verifies the
uncompressed arm64 Linux `Image` from the pinned PE/EFI kernel, compiles a static aarch64 syscall
probe, a root-only eBPF process-sensor bootstrap, and a separate unprivileged inert child fixture.
The tiny inert `/init` reports exact capability and sensor markers and powers off. Downloads,
generated images, serial output, and boot results belong under the gitignored `.whoathere/` tree.

The overlay uses a repository-owned canonical `newc` writer rather than host CPIO metadata. Entry
order, inode values, root ownership, modes, timestamps, and padding are fixed. The overlay is then
compressed with deterministic gzip settings before concatenation with Alpine's gzip initramfs. Two
clean builds from the same ISO must therefore produce byte-identical raw kernel, overlay, combined
initramfs, and manifest bytes.
The base builder requires Xcode's Clang and Zig; the independent verifier additionally uses `jq`,
`cpio`, `file`, and `shasum`. The signed overlay builder also requires pinned Rust,
`cargo-zigbuild`, and `unsquashfs`.

```sh
scripts/build-alpine-inert-image.sh \
  /absolute/path/alpine-virt-3.24.1-aarch64.iso \
  /absolute/path/output
```

Independently verify the pinned source hash, canonical manifest, every measured output, exact CPIO
entry set, extracted overlay contents, static probe format, combined initramfs construction, and
required kernel configuration:

```sh
scripts/verify-alpine-inert-image.sh \
  /absolute/path/alpine-virt-3.24.1-aarch64.iso \
  /absolute/path/output
```

Build and verify the separate guest-signing overlay with a protected seed. The seed and every image
containing it must remain under restricted, gitignored storage:

```sh
scripts/build-alpine-signed-inert-image.sh \
  /absolute/path/alpine-virt-3.24.1-aarch64.iso \
  /absolute/protected/guest-ed25519.seed \
  /absolute/path/signed-output

scripts/verify-alpine-signed-inert-image.sh \
  /absolute/path/alpine-virt-3.24.1-aarch64.iso \
  /absolute/protected/guest-ed25519.seed \
  /absolute/path/signed-output
```

On a physical Apple Silicon Mac with `kern.hv_support=1`, build and sign the dedicated
Virtualization.framework helper, then perform one inert boot into a new run directory:

```sh
scripts/run-alpine-inert-boot.sh \
  /absolute/path/alpine-virt-3.24.1-aarch64.iso \
  /absolute/path/output \
  /absolute/path/new-run-directory
```

The VM has no storage and no directory shares. Its sole NIC terminates at a host datagram socket
that provides no route. Success requires an exact kernel/initramfs digest binding, VM shutdown, no
raw frames, and exact serial lines proving the pinned kernel release and architecture, BTF, cgroup
v2, bpffs, fanotify, a BPF program load, virtio-net, no external route, no package execution, and no
sync-back. A host without hardware virtualization emits a fail-closed preflight record and does not
attempt a boot.

The generated manifest remains `candidate_unqualified`. The process bootstrap uses protected BPF
map counters to require a cgroup-filtered fork/exec/exit chain from a fixture running as UID/GID
65534, after closing sensor descriptors. The fixture must prove read and write denial against the
root-only sensor. These exact markers are still not an authenticated conformance receipt, do not
qualify the backend, and cannot authorize package execution. Only the complete authenticated
38-case inert conformance matrix can construct the distinct qualified backend type.

The first physical-host boot passed all thirteen exact capability checks with zero raw frames and all
three safety invariants false. See the
[sanitized inert-boot checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-inert-boot-checkpoint-2026-07-11.md).
The follow-on
[process-sensor checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-process-sensor-checkpoint-2026-07-11.md)
records the first successful root-owned cgroup-filtered process observation.
The
[ordered process-evidence checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-ordered-process-evidence-checkpoint-2026-07-11.md)
adds one canonical payload that independent Swift and Rust validators bind to the existing guest
receipt claim shape. It remains unsigned bootstrap evidence rather than a conformance receipt.
The
[measured backend-identity checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-measured-backend-identity-checkpoint-2026-07-11.md)
pins the runtime BTF and binds the actual physical-host helper, configurations, and fresh evidence
public keys into the still-unqualified backend identity.
The
[live guest-receipt checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-live-guest-receipt-checkpoint-2026-07-12.md)
adds a bounded host-CID-only virtio-vsock challenge, root-only guest signer, reproducible signed
initramfs overlay, and independently verified inert guest receipt. It does not qualify the backend.
The
[first complete conformance-case checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-first-complete-conformance-case-checkpoint-2026-07-12.md)
adds the separately signed host packet/lifecycle receipt and verifies the first physical
guest-plus-host case. The other 37 physical cases remain pending.
The
[file-telemetry checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-file-telemetry-checkpoint-2026-07-12.md)
adds fanotify permission evidence, BPF-correlated mmap, fake persistence, and protected filesystem
diffs, then rebaselines the process case on the same identity. The other 36 cases remain pending.
The distinct
[mmap checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-mmap-checkpoint-2026-07-12.md)
then verifies `mmap_access` on that exact identity. The other 35 cases remain pending.
The
[double-fork checkpoint](../../../docs/product-build-run/artifact-native-linux-vz-double-fork-checkpoint-2026-07-12.md)
adds protected double-fork lineage and daemon teardown, then reruns the earlier three cases on the
new measured identity. The other 34 cases remain pending.

## Closed fixture contract

`guest/fixture_cases.def` is the single ordered action table for the canonical 38-case matrix. It
fixes each case's fixture family, terminal semantics, trigger owner, inert action name, and network
policy. The only network policies are no network, the no-route guest sinkhole, and injected host
sinkhole overflow.

The accompanying inspector is intentionally non-executing. Its only operations are `--list` and
`--describe CASE`; it has no command, path, environment, package-byte, or execution input. Verify
the table against the canonical Rust enums and build the deterministic static aarch64 descriptor:

```sh
scripts/verify-fixture-contract.sh
cargo test --manifest-path ../../../Cargo.toml \
  -p whoathere-macos-vm \
  --test linux_vz_fixture_contract_v1
```

The descriptor is not the guest runner and is not bound as one. It cannot run a fixture, emit a
receipt, qualify telemetry, or authorize package code. Implementing each named action remains a
separate measured step after the inert image boots.
