# Artifact-Native npm Guest Identity Binding Checkpoint

Date: 2026-07-10

Status: package UID/GID and guest authentication public-key identity added to the measured Mac run
spec and base verifier; no authentication handshake, private-key provisioning, VSOCK listener, VM
boot, package execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Disposable Lifecycle Primitives Checkpoint](artifact-native-npm-disposable-lifecycle-primitives-checkpoint-2026-07-10.md)
- [Artifact-Native npm Guest Staging Checkpoint](artifact-native-npm-guest-staging-checkpoint-2026-07-10.md)

## Outcome

The Mac backend identity now binds the dedicated nonzero package UID and GID that the future root
supervisor must use. These numeric identities are part of the canonical run-spec digest and the
derived execution binding; they cannot be selected from mutable guest configuration or asserted
only after execution. Rust and Swift both require the fields, reject zero, and expose them only as
validated backend identity.

The identity also binds the SHA-256 of a 32-byte Ed25519 guest-authentication public key. The Swift
base layout gives that key a fixed `artifact-supervisor-public-key.bin` name. The stopped-base
verifier opens it with the same no-follow, ownership, link, mode, lock, and descriptor-hash controls
as the other measured inputs, requires exactly 32 bytes and the run-spec digest, and retains the
bytes with the locked base.

This closes two prerequisites for an authenticated guest handshake. It does not implement or claim
that handshake. A future host challenge must be signed by a root-only private key in the guest and
verified with these measured public-key bytes before the helper forwards any artifact. Merely
self-reporting the supervisor digest or package UID over VSOCK will not count as authentication.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Swift helper protocol, lifecycle, and guest transport tests | 23 passed, 0 failed |
| Rust Mac backend unit/integration tests with all targets | 20 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 686 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust and Swift production builds/format checks | passed |
| `git diff --check` | passed |

Tests cover Rust/Swift canonical interoperability with the expanded backend identity, exact public
key file measurement and capture, expected package UID/GID decoding, and zero-UID run-spec
rejection. Existing base digest, symlink, runtime, APFS clone, guest stream, staging, rehash, and
cleanup tests remain green.

All identities and key bytes were inert deterministic fixtures. No private key, real signature,
cloud Mac, VM, VSOCK connection, package process, npm process, network, registry, or restricted
sample was used.

## Open gates

The next landing is the nonce-based Ed25519 guest authentication protocol and bounded staging
receipt. The host must generate a fresh per-run nonce after accepting the dedicated connection,
bind it to the execution/run/base/clone identities, verify the guest signature with the measured
public key, and reject replay or connection races before forwarding the artifact. Private-key
generation, root-only custody, base-receipt binding, and rotation need explicit provisioning work.

Real-malware execution remains outside this goal's authorization.
