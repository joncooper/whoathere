# Artifact-Native Linux VZ Package Execution-Runtime Qualification Checkpoint

Date: 2026-07-15

Status: the exact execution-capable package root runtime and read-only Node/npm/Python/pip rootfs
passed two inert physical qualifications on the approved cloud Mac. No execution grant was issued,
no package or malware ran, no external frame was emitted, and sync-back remained unavailable.

## What This Checkpoint Closes

The measured guest runtime now has one production-shaped, closed execution entrypoint. It:

- accepts package execution only through fixed descriptor flags, not a caller-supplied executable,
  argv vector, shell fragment, working directory, or environment;
- reconstructs the exact non-authorizing package request from canonical bytes plus the exact
  artifact and typed scenario inputs;
- verifies and burns a short-lived Ed25519 one-use execution grant against the measured runtime,
  rootfs, runtime manifest, qualification record, artifact, scenario, telemetry backend, guest and
  host evidence keys, fresh challenges, and clone binding;
- burns the derived execution request before validating artifact or scenario bytes;
- performs the qualified root-coordinator split before constructing the protected signing
  authority;
- passes only root-owned, mode-`0444`, single-link artifact and optional closure descriptors to the
  hardened runner branch;
- drives the fixed npm, wheel, or sdist process plan through the concrete multi-action protected
  sensor service; and
- returns bounded digest-framed transcripts and authenticated root evidence that still require
  independent host composition and cannot authorize a verdict or sync-back.

The candidate runtime rootfs is a reproducible 1 GiB raw ext image containing the exact pinned
Node/npm and Python/pip toolchain. The runtime manifest now hashes the shared runtime-input
validation script in addition to the lockfile, container identity, builder sources, Cargo lock,
workspace manifest, complete Rust source closure, rootfs, archive, runtime, and toolchain binaries.

The qualification-only Mac VM configuration has:

- one read-only virtio block device;
- one file-handle network attachment terminating in the bounded host raw-frame collector with no
  forwarding route;
- no writable storage, directory share, or virtio-socket device; and
- a fixed init that verifies the exact manifest, disk, runtime, Node, npm, Python, and pip bytes,
  checks the read-only mount physically, exercises the exact coordinator split, and then powers
  off.

The Mac harness requires a separate canonical qualification-image manifest and binds it to the
exact runtime manifest, rootfs, initramfs, runtime, toolchain, and guest evidence key before it can
start the VM. It rehashes those inputs after VM stop.

## Reproducibility And Static Gates

The final stripped static aarch64 runtime was rebuilt from the current tree and matched the prior
runtime byte-for-byte:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| package root runtime | 4,535,048 | `87ad944bc5e2bcd8c80b1daed6457cdd83ff7e79d5917f994d53c5b37d7dcdeb` |
| rootfs ext image | 1,073,741,824 | `0fb5b03920aa3125d5d27c320eea9bb4b5eb5d1bb17bd12b3578db68480bd907` |
| canonical rootfs archive | 143,278,080 | `c22648bd423de3c5eb337d42528c441dfbb827d869bf7d3f84318779e7cf37db` |
| runtime input lock | 9,173 | `62f520de93071a90ce8bba75096ef147767357230e7b72271b2a5c46ee0262b0` |
| final runtime manifest | 2,645 | `042a6a42af066d14ebd6ab5517751eb180e6dbd7214a0b1c8cf938e81ba4fb38` |

Two final offline builds produced identical copies of all five outputs. The exact offline
archive-to-ext-filesystem, ownership, mode, toolchain, and closed-entrypoint verifier passed on the
same rootfs and runtime bytes. The final manifest differed only to add the shared-script provenance
and then update the current Rust source-closure digest; that closure digest was independently
recomputed as
`sha256:602c786ec8b654cda4b4a5002a5a96fa710f4a25ac56365987d17bcd8480684f`.

The code gates passed:

- 243 Rust library tests after the final source change;
- the preceding complete crate test sweep, including every binary and integration test;
- `cargo fmt --all -- --check`;
- native macOS Clippy with warnings denied;
- Linux/aarch64 Clippy with warnings denied; and
- 230 Swift tests.

The cloud Mac's complete-package Swift release build also encountered a compiler type-check timeout
in the unchanged general helper target. Building the explicitly scoped
`whoathere-linux-vz-conformance` product succeeded, and that product was signed with the required
virtualization entitlement and strictly verified before both VM runs.

## Qualification Image Identity

The module-bearing base initramfs was recovered as the exact prefix already recorded by the prior
successful inert qualification image, rather than assembling new module bytes:

| Component | SHA-256 |
| --- | --- |
| kernel | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| measured module-bearing base initramfs | `7cc5eaf5019e7bb33815ec79088aefdf4a154e6f229c17397b87e22b9a5dbd3d` |
| qualification init | `16cca82b9b0cdc05b7435d764e804b030c6baf0bc5304ba9fb7a4edc0a8d946b` |
| qualification overlay CPIO | `bd58603c35d556481107debc695e2284f9bd17d9c38d7b6850f3ff587aba32b6` |
| qualification overlay gzip | `d9f18695f7bdcddadd10fd7c2f7b81951326d90c571c21a5af611de12333fa5a` |
| final qualification initramfs | `862bbcb8f88dd6a5ae703a3e18e594731a22e8449e84cf7be754aa2be588fb4e` |
| qualification-image manifest | `478148c97a470cd3ee4218caf3b53eac0dbf577408e92ea85e4640641a45ac5a` |
| signed Mac verifier | `b410e94d0081f6ec9b87be64927f5662ef5bb9271a1d3b8dd90b6ec7583c9fdb` |
| guest evidence public key | `7d0f3e2fd73466b0920f237816020d051276816a885de9813bb3d1d30be86790` |

Two independent qualification-image builds were byte-identical for the init, embedded runtime
manifest, CPIO, gzip member, final initramfs, and image manifest.

## Physical Results

The first attempt used the pinned minimal Alpine base initramfs. It failed closed before the runtime
probe because that base did not contain the required virtio-block and ext modules. The VM stopped,
image identities remained stable, the raw-frame count and all frame-loss counters were zero, and
package execution, malware execution, execution authority, and sync-back all remained false.

The builder also initially exposed a mode-handling defect: the provider's read-only base initramfs
was copied with a non-writable mode, preventing the private output from being appended. The builder
now makes only its private copy owner-writable before appending; it never mutates the base input.

Both final physical runs passed. In each run the independent Mac verifier required:

- `status: ok`, `exit_code: 0`, valid canonical probe evidence, every required marker, no failure
  marker, and a stopped VM;
- stable kernel, initramfs, rootfs, runtime manifest, and qualification-image manifest identities;
- an exact read-only root disk, zero writable disks, zero directory shares, and no external route;
- zero received, retained, dropped, or truncated raw frames and a healthy host packet collector;
- one runner thread and exactly four expected runner descriptors;
- root credentials, tracer absence, no-new-privileges, non-dumpable runner and service, parent-death
  `SIGKILL`, closed seed descriptor in the runner, exact seed EOF, and zero unexpected descriptors;
- `CAP_SYS_PTRACE` absent from the inheritable, permitted, effective, bounding, and ambient sets,
  with the entire ambient set zero; and
- no execution authority, execution grant, execution request, package execution, malware
  execution, or sync-back.

Run-specific sanitized identities were:

| Run | Evidence payload SHA-256 | Host result SHA-256 | Serial SHA-256 |
| --- | --- | --- | --- |
| final C | `5d0e82bc23752cdf64d49990dc5aa6220f22f57bb604a0352a853fc640e1a388` | `c4e3d0bc916c6fb9dc882edc488ebaaa99dde38bf3fafa4def58de115c74d554` | `d047aa8e74057fa65cb0c8e32b97f0721135b70130bcd9e9d8d6b860f7c209d9` |
| final D | `707cf3347055cc8f1278ffb139e435bb0530d2539867498b9ec977f41addcc1c` | `0c121eb53e9373d50951d40401b0b2dfd21c037c463972e63ccefacab6e3a80f` | `6e6647b7a55b5540144a01cba40b9e3996d0a034178f9e4bbe76a4c6aca5744e` |

The differing evidence digests reflect distinct physical service and runner process identities;
the measured image and policy identities remained identical.

## Claim Boundary And Next Gate

This checkpoint qualifies the exact execution-capable runtime composition and proves its
qualification-only coordinator custody path on the approved Mac. It does **not** prove that a real
package completes an npm, wheel, or sdist workflow, that the execution grant and authenticated
root evidence compose correctly across a physical package run, or that any malicious behavior is
detected.

The next gate is one purpose-built inert npm artifact through one signed, short-lived grant and the
fixed typed npm scenario. That run must preserve the same no-route/no-sync posture and produce
authenticated root evidence plus independent host composition before wheel or sdist execution is
attempted. Real malware remains out of scope until those inert gates pass and the user separately
approves a controlled lab campaign.

The July actual-malware score remains **7/11 (63.6%)**. This checkpoint improves execution
integrity and evidence trust; it does not count as a malware detection.
