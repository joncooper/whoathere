# Artifact-Native npm Guest Authentication Checkpoint

Date: 2026-07-10

Status: cross-language nonce-based Ed25519 guest authentication contract implemented and verified;
no control-frame/VSOCK wiring, guest private-key loading or provisioning, VM boot, artifact forwarding,
package execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Guest Identity Binding Checkpoint](artifact-native-npm-guest-identity-binding-checkpoint-2026-07-10.md)
- [Artifact-Native npm Guest Streaming Transport Checkpoint](artifact-native-npm-guest-streaming-transport-checkpoint-2026-07-10.md)

## Outcome

WhoaThere now has matching Rust and Swift contracts for authenticating the separate root guest
supervisor before the helper forwards an artifact. The host challenge binds a fresh 256-bit nonce,
the exact execution binding, complete run-spec digest, unique disposable-clone binding, and measured
guest-authentication public-key digest. Challenge JSON is closed, bounded, and byte-canonical.

The guest response binds the challenge digest, execution, run spec, clone, guest-supervisor binary,
runner configuration, and dedicated package UID/GID. Rust signs a domain-separated message containing
both the exact canonical challenge and the exact canonical unsigned response. Swift reconstructs
that message and verifies the Ed25519 signature with CryptoKit and the public-key bytes captured from
the locked measured base.

This prevents an unprivileged guest process from winning a connection race merely by repeating
self-asserted identities. It also prevents a valid old response from authenticating a fresh nonce or
a different run, clone, supervisor, runner, UID, or GID. The host must still create the nonce only
after accepting the dedicated one-shot connection and must not forward bytes until verification
succeeds.

## Clone and key binding

The Swift clone binding is domain-separated over the measured base generation, random clone/run ID,
cloned disk digest, and cloned auxiliary-storage digest. Two clones of the same base and artifact
therefore receive different guest-authentication challenges.

Rust derives the Ed25519 public key from the private seed before signing and refuses to sign if its
SHA-256 does not match the challenge's measured public-key identity. The seed argument is zeroized,
and the signing-key type uses its zeroization support. This is a protocol primitive: no private key
file, Keychain item, Secure Enclave key, or base-provisioning workflow was created in this landing.

## Canonical cross-language vector

The repository includes a deterministic Rust vector using a test-only seed, fixed nonce, fixed
bindings, and fixed claims. Rust asserts the complete canonical challenge, canonical response, and
signature bytes. Swift decodes the exact Rust challenge and verifies the exact Rust signature with
the derived public key. This catches JSON ordering, digest, message-layout, Ed25519, and hex-encoding
drift across the language boundary.

The deterministic seed and signature are inert test material and have no production authority.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Swift helper protocol, authentication, lifecycle, and transport tests | 26 passed, 0 failed |
| Rust Mac backend unit/integration tests with all targets | 21 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 687 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting, production Swift build, and `git diff --check` | passed |

Tests cover exact Rust-to-Swift signature verification, strict canonical challenge decoding, measured
public-key mismatch, nonzero package identities, signed-claim substitution, signature mutation,
fresh-nonce replay rejection, and distinct clone bindings. Existing transport, APFS, staging,
prelaunch/postrun rehash, and cleanup tests remain green.

No production key, cloud Mac, VM, VSOCK connection, package process, npm process, network, package
registry, or restricted sample was used.

## Open gates

The next landing must add bounded domain-separated control frames on the dedicated VSOCK channel:
host challenge, guest signed response, artifact body, and a final non-executing staging receipt. The
root supervisor also needs reviewed private-key generation, root-only custody, rotation/revocation,
and post-provisioning receipt binding. A fresh host challenge must be consumed once and connection
closure must be recorded before any successful lifecycle observation.

Real-malware execution remains outside this goal's authorization.
