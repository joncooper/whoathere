# Artifact-Native Linux VZ Inert-Boot Checkpoint

Date: 2026-07-11

Status: the pinned Linux VZ candidate boots successfully on an independently identified physical
Apple Silicon Mac and passes the twelve exact inert capability checks; the backend remains
unqualified because protected sensors and the authenticated 38-case conformance matrix have not run

Follow-on: the
[process-sensor bootstrap checkpoint](artifact-native-linux-vz-process-sensor-checkpoint-2026-07-11.md)
adds the first real cgroup-filtered fork/exec/exit observation, but still no signed conformance
receipt or qualified backend.

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Inert-Image Candidate Checkpoint](artifact-native-linux-vz-inert-image-candidate-checkpoint-2026-07-11.md)
- [Linux VZ Conformance Run-Spec Checkpoint](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md)
- [Linux VZ Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The candidate completed one canonical inert boot on an arm64 Mac with hardware virtualization.
The guest emitted the exact success marker and all twelve required capability lines. The host
result was canonical JSON with:

- `status=ok` and `exit_code=0`;
- `virtualization_supported=true` and `vm_stopped=true`;
- stable kernel and initramfs identities before and after the run;
- `missing_capability_markers=[]`;
- `raw_frame_count=0` on the host raw-frame sinkhole;
- `external_route=false`;
- `package_execution=false`; and
- `sync_back=false`.

The observed capabilities were:

| Capability | Exact observed state |
| --- | --- |
| Kernel | `6.18.35-0-virt` |
| Architecture | `aarch64` |
| Kernel BTF | `present` |
| cgroup v2 | `mounted` |
| BPF filesystem | `mounted` |
| `fanotify_init` | `available` |
| BPF program load | `available` |
| Static syscall probe | `passed` |
| virtio-net | `loaded` |
| External route configured | `false` |
| Package execution | `false` |
| Sync-back | `false` |

This establishes the minimum Linux-on-Mac platform feasibility needed for protected behavioral
telemetry. It does not establish that any malicious package is detected.

## Reproducible image identity

The successful candidate uses manifest schema
`whoathere.linux_vz_inert_image_manifest.v3`. Two independent local builds produced identical
manifest, raw kernel, compressed overlay, and combined initramfs bytes. The remote verifier then
recomputed the same hashes before boot.

| Object | SHA-256 |
| --- | --- |
| Official Alpine source ISO | `c81699152db11d2a6dbb7d75348d632fcf5811eff414d7e71876a8bb6d48bc02` |
| Alpine source PE/EFI kernel | `47970e0ee0478fe5c60824a89f162d5a353fa29466e5d3bddb0f9c506f1ed756` |
| Extracted arm64 Linux `Image` | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Alpine base initramfs | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Static capability probe | `2b592e9ef5775a368e65d546420e805a2cc6b3bd5bc1e54b5acce56189ae23cd` |
| Canonical overlay CPIO | `b275058449dc0f639942000041d02c2dabbcbc001d93b5fcc2aba1594cd76e9b` |
| Deterministic compressed overlay | `4abffbd4a7d98ec8928fd4673250a6ac3a2be57d4a24678a1be49941ba09e66b` |
| Combined initramfs | `1ad85dea3266edaaeb0a174863f2dcd408c009adf12c039326bc10af9e77d387` |
| Canonical manifest | `e3b55c7a6fee97ee3136d598bf592200cded59cf08fc4ab88498a11740c6be2e` |

The boot result binds the raw kernel and combined-initramfs hashes above. The command line was
`console=hvc0 rdinit=/init panic=0 reboot=k loglevel=6`.

## Engineering findings closed by the run

The qualification attempt exposed and closed four fixture-level issues without weakening any
gate:

1. Alpine's `vmlinuz-virt` is an aarch64 PE/EFI executable, while `VZLinuxBootLoader` required the
   embedded uncompressed arm64 Linux `Image`. The builder now extracts the pinned gzip payload at a
   pinned offset and verifies both source and extracted hashes plus the raw image format.
2. Appending a raw CPIO archive after Alpine's gzip initramfs caused the kernel to reject the second
   archive. The overlay is now independently compressed with deterministic gzip settings and the
   verifier proves the exact base-gzip-plus-overlay-gzip byte stream.
3. The early Alpine initramfs contains BusyBox without all normal applet symlinks. The inert init now
   invokes the measured BusyBox binary explicitly for setup and shutdown operations.
4. Foundation's default JSON serialization escaped the slash in `/init`, which was valid JSON but
   did not match the repository's canonical `jq -cS` form. The helper now emits sorted JSON without
   slash escaping, and the run script independently enforces canonical bytes.

Each intermediate failure remained fail closed. No generic block or corpus label was counted as a
capability success.

## Verification

The final implementation passed:

- two independent image builds with byte-identical manifest, raw kernel, compressed overlay, and
  combined initramfs;
- the independent local and remote image verifier;
- the canonical 38-case fixture-contract verifier;
- all 98 Swift helper tests;
- all 90 tests in the Rust macOS VM package;
- the full Rust workspace test suite;
- workspace Clippy with warnings denied and Rust formatting; and
- shell syntax checks for the inert init, builder, verifier, and boot runner.

The final remote run independently rebuilt and signed the dedicated helper, reverified the image,
booted the guest, validated exact serial lines rather than substrings, required canonical host
result JSON, and exited zero.

## Evidence custody and safety

The sanitized local evidence snapshot is gitignored under:

```text
.whoathere/remote-evidence-snapshots/linux-vz-inert-boot-2026-07-11-sanitized/
```

Its retained files and hashes are:

| Sanitized evidence | SHA-256 |
| --- | --- |
| Canonical boot result | `454875cfa9509df9f1a83f52c5f99437facacd17f784cab4fd41b2ff78162319` |
| Host preflight | `9efdf5213adb974d1e5f6ee183c639ad3fb6d9493639c97faad6cb8c30dcda5b` |
| Inert serial log | `3010019905b2551232e3e0f9a4c27de4616ffdc38884994fefa19798a9822f0b` |

The snapshot contains no package artifact, malware, credentials, canaries, provider identifiers,
remote address, or host-private working path. It must remain untracked.

The run used no package manager, package code, restricted sample, live C2, second stage, disk,
directory share, sync-back path, or public guest route. The sole guest NIC terminated at a host
datagram sinkhole with no forwarding path.

## Claim boundary and next gate

This checkpoint proves that the measured kernel and inert initramfs boot under
Virtualization.framework and that the required kernel facilities are available. The serial markers
are trusted-fixture assertions used to establish platform feasibility; they are not protected
behavioral telemetry and cannot qualify a backend or authorize package execution.

The next execution gate is to add the measured root-owned runner and protected process, file,
network, and sensor-health collectors, then run the authenticated 38-case inert conformance matrix
on unique disposable VZ instances. Only real verified receipts from every case may construct the
qualified backend type. Package execution remains disabled until that qualification succeeds.
