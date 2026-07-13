# Artifact-Native Linux VZ Runtime-Qualification Guest Candidate Checkpoint

Date: 2026-07-13

Status: implementation and reproducibility checkpoint; the final corrected image subsequently
passed inert physical qualification, while package execution remains unavailable

## Outcome

The first complete guest-side candidate for the inert package-runtime qualification run now exists.
It composes the already-qualified Linux VZ kernel, signed initramfs, protected process sensor, and
guest signer with a deterministic overlay containing only:

- a PID 1 bootstrap with no configured public route or resolver;
- the strict runtime-qualification agent;
- the exact candidate runtime manifest; and
- the pinned virtio block and ext filesystem module closure needed to observe `/dev/vda`.

The guest agent accepts one bounded request over virtio-vsock. It strictly decodes the canonical
false-authority request, remeasures its own executable and overlay inputs, verifies the runtime
manifest, streams the exact 1 GiB block device through SHA-256, checks its fixed ext filesystem
identity, and mounts it read-only with `nodev,nosuid`. It can invoke only the runtime's closed
`fork_exec_exit` probe through the already-qualified protected sensor. The exact fixed report and
one complete healthy process-evidence payload are required before the guest can produce the
domain-separated Ed25519 receipt. The filesystem is unmounted before the agent terminates.

No npm, pip, wheel, sdist, project, or package payload is accepted by this image. The only runner
surface is the fixed non-executing probe, whose report states that execution authority, package
execution, and sync-back are false.

## Host and verifier boundary

The Rust host request builder now:

- independently decodes the exact qualified telemetry record and its measured backend identity;
- streams the candidate rootfs instead of allocating its 1 GiB contents;
- remeasures the runtime manifest, package runner, qualification initramfs, agent, init, and module
  manifest;
- validates every relationship repeated in the qualification-image manifest;
- binds a fresh challenge and an exact canonical disposable-clone binding; and
- writes a bounded canonical request plus a distinct binary transport frame into a secure,
  pre-existing mode-0700 directory using exclusive mode-0600 files.

Rust and Swift independently decode the bounded three-part guest response, reconstruct the exact
unsigned receipt, validate the raw process-evidence payload, bind the fixed report and runtime
block-device identity, and verify the request-bound guest Ed25519 signature. Parsing or verifying
any of these objects cannot produce package execution authority.

## Reproducibility result

Two clean offline builds from the final source and pinned toolchain produced byte-identical output
trees. Both independent verification runs passed archive ordering and modes, gzip expansion,
base-plus-overlay initramfs composition, copied component identity, manifest bindings, ELF
architecture/static-linkage, module hashes, and closed policy checks.

Final candidate identities:

- qualification manifest: `sha256:74dd24aae8f023826b30c76ecc9ad8f192037f1b4b9497f2e8c70a2320aac86c`;
- complete Rust source closure: `sha256:ea72ffa2c6192d3db3e6c4ba96ba58f379869177ed378fc2b5fe1a748ab8779c`;
- qualification initramfs: `sha256:7cc5eaf5019e7bb33815ec79088aefdf4a154e6f229c17397b87e22b9a5dbd3d`;
- deterministic overlay cpio: `sha256:9083667cc404892e8946b158fcefabe290f708765a487eaffc5981f1fb5f88d3`;
- compressed overlay: `sha256:300e0db83b64d4bbc03469956905e41008bcafdc37e2b3288d92359fac3d4a20`;
- static ARM64 Linux guest agent: `sha256:1eb8fbb393ed2b373e6fa32f411150a91e32150fc6f044e302a05e8ac993ca93`;
- guest init: `sha256:8de1fd6b691caca7aa44a738522659c52652dad031e7e7714b69e872e09e4431`;
- runtime module manifest: `sha256:3239591ce70a23e813fc513b12a3c6b7641d86359fbca50d344c7a333d08d8d4`;
- candidate rootfs: `sha256:0114f1508ca2214787af2befc64641801f26904d7d6771cbb8cd9a746d7029ae`;
- candidate runtime manifest: `sha256:bcfa7106cd4a604af531b7c3320625a4434009a692bbde01c953ef61e2fb23a5`;
- candidate package runner: `sha256:96c9ab2127e11029c1b23259afcbd7dfab984ab3ae4528555f0a8b34dc48d658`.

The full Rust crate passed 181 tests across its library, binaries, and integration suites, with
formatting clean and Clippy warnings denied. The static ARM64 Linux guest cross-build succeeded
through the pinned Zig toolchain. The full Swift helper suite passed 197 tests. Shell syntax and
the canonical newc builder's warning-free C compilation also passed.

## Claim boundary

At the time it was first recorded, this checkpoint proved source-level protocol closure and byte
reproducibility rather than physical runtime behavior. The final corrected image listed above later
passed the separate
[physical qualification gate](artifact-native-linux-vz-runtime-qualification-physical-checkpoint-2026-07-13.md).
That result still does not issue a one-use package grant, execute npm or pip, inspect a package
artifact, improve the July malicious-package score, or support a malware claim.

Real malware remains restricted to the approved cloud Mac lab workflow. It may not run locally or
in Docker, and this checkpoint did not handle any real sample.

## Next gate

This gate is complete. See the
[host-launcher checkpoint](artifact-native-linux-vz-runtime-qualification-host-launcher-checkpoint-2026-07-13.md)
and the
[physical qualification checkpoint](artifact-native-linux-vz-runtime-qualification-physical-checkpoint-2026-07-13.md).
The next gate is one-use execution authority plus inert npm, wheel, and nested-sdist scenarios.
