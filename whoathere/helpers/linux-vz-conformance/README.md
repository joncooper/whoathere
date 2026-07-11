# WhoaThere Linux VZ Conformance Harness

This directory contains only trusted inert Linux-on-Mac qualification fixtures. It must not receive
package artifacts or malware.

The first boot input is Alpine Linux 3.24.1's official aarch64 virtual ISO, pinned by SHA-256. The
builder extracts the virt kernel, initramfs, config, and System.map, compiles a static aarch64 syscall
probe, and appends a tiny inert `/init` that reports capability markers and powers off. Downloads,
generated images, serial output, and boot results belong under the gitignored `.whoathere/` tree.

The overlay uses a repository-owned canonical `newc` writer rather than host CPIO metadata. Entry
order, inode values, root ownership, modes, timestamps, and padding are fixed. Two clean builds from
the same ISO must therefore produce byte-identical overlay, combined initramfs, and manifest bytes.
The builder requires Xcode's Clang and Zig; the independent verifier additionally uses `jq`, `cpio`,
`file`, and `shasum`.

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

The generated manifest remains `candidate_unqualified`. A successful boot marker is not protected
telemetry conformance, does not qualify the backend, and cannot authorize package execution. Only
the complete authenticated 38-case inert conformance matrix can construct the distinct qualified
backend type.

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
