# Artifact-Native npm Non-Executing Guest Session Checkpoint

Date: 2026-07-10

Status: authenticated single-connection host/guest state machine and signed non-executing staging
receipt implemented and cross-validated; no production guest supervisor wiring, VSOCK listener, VM
boot, package process, npm execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm Guest Control Framing Checkpoint](artifact-native-npm-guest-control-framing-checkpoint-2026-07-10.md)
- [Artifact-Native npm Guest Staging Checkpoint](artifact-native-npm-guest-staging-checkpoint-2026-07-10.md)
- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

## Outcome

Rust and Swift now share a strict, signed staging-receipt contract for the first artifact-native npm
VM slice. The receipt binds the fresh authentication challenge, execution and run-spec identities,
unique disposable-clone identity, exact original artifact digest and length, first guest rehash,
staged device and inode, package UID/GID, fixed `0444` artifact mode, fixed `0711` staging-directory
mode, and an explicit `package_execution_enabled: false` posture.

The Swift helper core composes the previously separate primitives into one ordered, non-executing
session:

1. lock and verify the complete measured base and unique APFS clone;
2. send a fresh typed authentication challenge;
3. receive and verify the measured guest's Ed25519 response;
4. only after authentication succeeds, stream the canonical header and exact raw artifact bytes;
5. close the host write side so the guest can prove the artifact frame ended;
6. receive and verify the signed staging receipt; and
7. require guest write-side EOF with no trailing frame or data.

The session result has no command, argv, package-manager call, execution toggle, sync-back path, or
allow authority. Its package-execution field is constructed as `false`; the receipt verifier also
requires the signed field to be false.

## Receipt trust properties

The host does not accept the receipt as an unauthenticated guest assertion. Before signature
verification it requires the authenticated observation to match the challenge hash, execution
binding, run-spec binding, clone binding, measured supervisor, measured runner configuration,
package UID/GID, and measured public key. It independently requires the artifact transport
observation to match the submission prelude.

Receipt JSON is closed, size-bounded, byte-canonical, and domain-separated from the authentication
signature. Decimal identity and length fields reject signs, whitespace, leading zeroes, and values
outside `UInt64`. The host requires positive device and inode values, identical original and first
rehash identities, exact modes, exact package credentials, a lowercase canonical Ed25519 signature,
and final channel EOF. Mutation of the no-execution field or an expected staging identity fails
closed.

The Rust contract creates the same canonical bytes used by the Swift golden-vector test. Its
signing entry point checks that the private seed corresponds to the public-key digest in the fresh
challenge and zeroizes the caller-provided seed copy after key construction.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Complete local Unix socket-pair state-machine test | passed |
| Swift helper authentication, receipt, control, lifecycle, protocol, and transport tests | 30 passed, 0 failed |
| Rust Mac backend unit and integration tests | 23 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 689 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting and production Swift build | passed |

The state-machine test uses a measured inert fixture base and unique APFS clone, completes the fresh
authentication exchange, transfers one exact repository-generated inert npm tarball, reconstructs
and validates its guest frame, signs the staging receipt with the fixture key, requires final EOF,
and proves the returned session cannot enable package execution. Cross-language tests verify a Rust
receipt in Swift and reject a canonical mutation that enables execution. Rust tests reject changed
staging identity and execution-enabled receipts.

No production key, cloud Mac, VM, VSOCK connection, package process, npm process, network, registry,
or restricted sample was used. The restricted eleven-sample regression gate remains unopened and
still requires the separate documented lab approval.

## Open gates

This checkpoint proves the host-side protocol composition and cross-language receipt semantics; it
does not prove that a measured guest supervisor performs them inside a VM. The next slice must:

1. package the Rust receiver, staging lifecycle, authentication signer, and receipt signer into a
   separately installed root-owned guest supervisor;
2. load its private key from the measured guest with permissions inaccessible to the package UID;
3. bind only the dedicated VSOCK port and accept exactly one bounded scenario session;
4. connect the Swift lifecycle to a real inert VM boot and VSOCK connection;
5. impose bounded boot, handshake, staging, stop, and clone-cleanup deadlines with fault injection;
6. prove VM stop and clone absence after success and every injected failure; and
7. still stop before spawning npm or any artifact-controlled process.

Only after that inert lifecycle is verified should the package-user execution supervisor, typed npm
lifecycle scenario, protected telemetry, and verdict path be connected. Real-malware execution
remains outside this goal's authorization.
