# Artifact-Native Linux VZ Runtime-Qualification Guest Candidate Checkpoint

Date: 2026-07-13

Status: the deterministic runtime-qualification guest image, strict host request builder, and
independent guest-receipt verifiers are implemented and reproducible; the image has not booted,
the candidate runtime remains unqualified, and package execution remains unavailable

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

- qualification manifest: `sha256:1a633affee36d9bf3cc57c8895d7c2c8c3f5932259f53cac258d412aa5cc147e`;
- complete Rust source closure: `sha256:d6012b0117eb3082078d6c0ea12e5340347e5ad2a5f819b8068bc65829a62bbb`;
- qualification initramfs: `sha256:4393945d789691ff41667b2f24d92bcbffaf1a0ed2edd3e8c72e34fcf2ba995b`;
- deterministic overlay cpio: `sha256:60330e14cd04c2eba30f997c5d775cfa49fd40ad8ff8990e072d590366f7cdcb`;
- compressed overlay: `sha256:7cf7cfe7cbdef6317da74544ca2e4a43fdb00319992d22cfd15c71f2581704f9`;
- static ARM64 Linux guest agent: `sha256:3288dcd93432c424807b75f05c16754435686dcc8486fb2b669c2324ca29b366`;
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

This checkpoint proves source-level protocol closure and byte reproducibility, not physical
runtime behavior. No VZ VM was started, no block device was attached, no receipt was returned by a
live guest, no host lifecycle receipt was signed, and the candidate runtime is still unqualified.
It does not issue a one-use package grant, execute npm or pip, inspect a package artifact, improve
the July malicious-package score, or support a malware claim.

Real malware remains restricted to the approved cloud Mac lab workflow. It may not run locally or
in Docker, and this checkpoint did not handle any real sample.

## Next gate

Implement and test the minimal macOS launcher that owns one measured APFS rootfs clone, one VZ VM,
one no-forwarding raw-frame attachment, and one bounded vsock exchange. It must independently verify
the guest receipt, prove zero observed/external frames, stop the VM, destroy the clone only after
stop, and sign a separate exact host lifecycle receipt. Then transfer only inert measured inputs to
the approved cloud Mac for one physical qualification run.
