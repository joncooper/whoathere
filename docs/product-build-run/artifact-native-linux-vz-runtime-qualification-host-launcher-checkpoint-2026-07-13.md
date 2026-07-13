# Artifact-Native Linux VZ Runtime-Qualification Host Launcher Checkpoint

Date: 2026-07-13

Status: the fail-closed macOS launcher and independently verified host lifecycle receipt are
implemented and pass local non-boot preflight; no runtime-qualification VM has booted and the
candidate runtime remains unqualified

## Outcome

The inert runtime-qualification candidate now has a single-purpose macOS host launcher. It owns the
entire physical lifecycle rather than delegating safety-critical state to a shell script:

1. strictly decode the qualified telemetry record and measured backend identity;
2. remeasure the source-closed qualification image and pinned candidate runtime;
3. lock the base runtime and create one distinct writable APFS clone;
4. invoke the strict Rust request builder with that exact clone binding;
5. independently decode and cross-bind the resulting canonical request in Swift;
6. configure one Linux VZ VM with the qualified kernel, qualification initramfs, one clone, one
   no-forwarding raw-frame socket, one serial channel, one vsock device, and no directory shares;
7. send one bounded request to guest port 40554 and accept one bounded response;
8. verify the protected process evidence and guest Ed25519 receipt;
9. require a stopped VM, healthy drained packet sinkhole with zero frames, stable image and clone
   identity, and complete exact serial markers;
10. destroy the clone only after stop is proven; and
11. create and verify a separate host-key-signed lifecycle receipt before writing success outputs.

Every success object states that execution authority, package execution, external routing, and
sync-back are false. The launcher contains no npm, pip, wheel, sdist, package, or malware input.

## Fail-safe lifecycle correction

The disposable runtime clone no longer relies on an unconditional destructor cleanup when VM state
is uncertain. If the launcher cannot prove the VM stopped, it marks the clone for preservation and
closes its descriptors without unlinking the possibly attached disk. Explicit cleanup remains
available after an operator proves stop. Unit coverage verifies that this path preserves the run
directory. Normal pre-VM failures and proven-stopped paths still destroy the clone.

## Authenticated host evidence

The host evidence is a canonical six-event record:

- clone created and bound;
- VM started;
- guest response completed;
- raw-frame sinkhole drained;
- VM stopped; and
- clone destroyed after stop.

It binds the exact request frame, response frame, guest receipt, process evidence, probe report,
serial-log digest, request challenge, and clone binding. A valid record requires zero raw frames,
zero host drops, zero forwarded frames, a healthy packet sensor, terminated guest channel, stable
image identity, stopped VM, and destroyed clone.

Swift signs a domain-separated receipt that length-prefixes the exact canonical request, host
evidence, and unsigned receipt. Swift independently verifies it before success. Rust separately
reconstructs the entire host evidence and unsigned receipt, validates the request/response frames,
and verifies the request-bound host key and Ed25519 signature. A fixed cross-language golden proves
that both implementations produce the same evidence and unsigned receipt bytes and that Rust
accepts a Swift-generated signature. The independent Rust CLI is ready to reverify physical output.

## Final reproducible image

The launcher work changed the linked Rust crate, so the guest image was rebuilt only after the host
protocol and independent verifier stabilized. The build manifest now binds the complete sorted Rust
source closure, including path and byte length, in addition to the agent source and Cargo lock.
Two fresh offline builds produced byte-identical trees and both passed the independent verifier.

Current physical-candidate identities:

- qualification manifest: `sha256:1a633affee36d9bf3cc57c8895d7c2c8c3f5932259f53cac258d412aa5cc147e`;
- Rust source closure: `sha256:d6012b0117eb3082078d6c0ea12e5340347e5ad2a5f819b8068bc65829a62bbb`;
- qualification initramfs: `sha256:4393945d789691ff41667b2f24d92bcbffaf1a0ed2edd3e8c72e34fcf2ba995b`;
- static guest agent: `sha256:3288dcd93432c424807b75f05c16754435686dcc8486fb2b669c2324ca29b366`;
- candidate runtime rootfs: `sha256:0114f1508ca2214787af2befc64641801f26904d7d6771cbb8cd9a746d7029ae`;
- candidate runtime manifest: `sha256:bcfa7106cd4a604af531b7c3320625a4434009a692bbde01c953ef61e2fb23a5`;
- candidate package runner: `sha256:96c9ab2127e11029c1b23259afcbd7dfab984ab3ae4528555f0a8b34dc48d658`.

## Local non-boot preflight

The launcher was exercised locally with every exact inert image, backend, and runtime input but a
deliberately wrong guest public key. It created and independently decoded the fresh request, failed
at request-context verification before creating serial, raw-frame, or VZ objects, emitted a
machine-readable false-authority failure, and returned exit 70. The disposable runtime run
directory was empty afterward, proving cleanup on this pre-VM failure path.

The full Rust crate passes 181 tests with formatting clean and Clippy warnings denied. The Swift
helper, including the new launcher product, passes 197 tests and a complete debug build. The
launcher usage path also returns a structured false-authority exit 64 without touching VZ.

## Claim boundary

No VZ VM was started locally or remotely for this checkpoint. No live guest receipt or host
lifecycle receipt exists yet, and the runtime is not qualified. No package manager ran, no package
artifact was processed, no one-use execution grant exists, and no detection result changed.

Real malware remains restricted to the approved cloud Mac lab workflow. This checkpoint did not
download, inspect, unpack, transfer, or execute any real sample.

## Next gate

Transfer only the measured inert qualification image, candidate runtime, qualified backend inputs,
public verification keys, and built host/request/verifier tools to the approved cloud Mac. Run one
inert physical qualification, independently reverify both signed receipts and zero-frame lifecycle
evidence, and preserve only sanitized hashes and false-authority claims in tracked documentation.
Do not transfer or run malware for this gate.
