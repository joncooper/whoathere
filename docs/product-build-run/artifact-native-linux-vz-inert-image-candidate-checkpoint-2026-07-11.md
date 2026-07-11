# Artifact-Native Linux VZ Inert-Image Candidate Checkpoint

Date: 2026-07-11

Status: a pinned, reproducible, independently verified inert Linux VZ boot candidate exists; the
current development host has no Virtualization.framework hardware support, so no guest boot,
sensor observation, conformance receipt, backend qualification, or package execution has occurred

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Linux VZ Conformance Run-Spec Checkpoint](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md)
- [Linux VZ Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The repository now contains a dedicated Linux VZ inert-image builder, independent verifier, inert
boot runner, fixed guest init, static aarch64 capability probe, and canonical `newc` writer. The
builder accepts only the exact official Alpine Linux 3.24.1 aarch64 virt ISO digest and emits a
canonical `candidate_unqualified` manifest.

The canonical archive writer fixes CPIO entry order, inode values, uid/gid, modes, timestamps, and
padding. This removes host filesystem inode metadata from the combined initramfs identity. Two
clean output directories built from the same source ISO produced byte-identical overlay,
initramfs, probe, and manifest bytes.

The current measured candidate is:

| Object | SHA-256 |
| --- | --- |
| Official Alpine source ISO | `c81699152db11d2a6dbb7d75348d632fcf5811eff414d7e71876a8bb6d48bc02` |
| Alpine virt kernel | `47970e0ee0478fe5c60824a89f162d5a353fa29466e5d3bddb0f9c506f1ed756` |
| Alpine base initramfs | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Static capability probe | `2b592e9ef5775a368e65d546420e805a2cc6b3bd5bc1e54b5acce56189ae23cd` |
| Canonical overlay CPIO | `be89c13ce5f8db1339ad365e5a43af10f0bee29c08c7ce8721fd6e4f90489966` |
| Combined initramfs | `fb9356b9be8e0c72e39f178ee646d0f49a674075d70a37ee2c81f8689b5df9d0` |
| Canonical manifest | `828316dc07cfabba1314b3ba97b277f14934acb0a1b181b0f6129778c8d66e7c` |

The static probe directly attempts `fanotify_init` and a minimal
`BPF_PROG_TYPE_SOCKET_FILTER` load. The inert init separately requires the pinned kernel release and
architecture, kernel BTF, cgroup v2, bpffs, virtio-net, no configured external route, no package
execution, and no sync-back before it emits the exact success marker.

## Host containment contract

The dedicated Swift executable constructs a Linux VZ configuration with:

- `VZGenericPlatformConfiguration` and `VZLinuxBootLoader`;
- the exact measured kernel and combined initramfs;
- no storage devices and no directory shares;
- one virtio NIC attached to a host datagram socket with no forwarding path;
- one serial port, one vsock device, and one entropy device; and
- fixed command line `console=hvc0 rdinit=/init panic=-1 reboot=k loglevel=6`.

The helper requires caller-supplied expected kernel and initramfs digests, rejects a mismatch before
configuration, and rehashes both paths after VM stop. Success requires stable image identity, the VM
to stop, the exact success line and all twelve exact capability lines, and zero raw frames.
Substrings do not count as markers. The result schema repeats `external_route=false`,
`package_execution=false`, and `sync_back=false`.

## Verification

The following completed successfully:

```sh
sh -n \
  whoathere/helpers/linux-vz-conformance/guest/init \
  whoathere/helpers/linux-vz-conformance/scripts/build-alpine-inert-image.sh \
  whoathere/helpers/linux-vz-conformance/scripts/verify-alpine-inert-image.sh \
  whoathere/helpers/linux-vz-conformance/scripts/run-alpine-inert-boot.sh

swift test --filter linuxVzInert
swift test
swift build -c release --product whoathere-linux-vz-conformance
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
```

The focused Swift run passed four tests covering the zero-storage/share topology, input rejection,
and exact serial marker validation. The full Swift suite passed 98 tests, the Rust macOS VM package
passed 88 tests, Clippy passed with warnings denied, formatting passed, and the dedicated Swift
product built in release mode. The image verifier independently checked the canonical manifest and
key set, all source/output digests, exact three-entry overlay and contents, static stripped aarch64
probe, base-plus-overlay construction, and required kernel configuration. A deliberately wrong
expected kernel digest was rejected before VM configuration.

The current host emitted a fail-closed preflight with `virtualization_supported=false`; the helper
also returns the distinct `virtualizationUnsupported` error. No VM was started. A configured remote
physical Mac remains ineligible because its changed SSH host identity has not been independently
confirmed; strict host-key checking was not weakened.

## Claim boundary and next gate

This checkpoint proves reproducible candidate bytes and host-side inert configuration logic only.
It does not prove that the Alpine kernel format is accepted by `VZLinuxBootLoader`, the appended
init runs, any capability succeeds in a guest, the raw-frame sinkhole observes correctly, a VM
stops cleanly, or protected telemetry works.

The next authorized step is one inert boot on an independently identified physical Apple Silicon
Mac. If that succeeds, retain only sanitized host preflight, image/result digests, exact capability
statuses, VM-stop state, and raw-frame count. Then implement the protected sensors and execute the
closed 38-case inert conformance matrix on unique disposable clones.

No package artifact, package manager, package code, restricted sample, malware, live C2, second
stage, sync-back path, or public guest route was used.
