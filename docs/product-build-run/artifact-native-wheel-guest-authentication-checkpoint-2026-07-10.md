# Artifact-Native Wheel Guest Authentication Checkpoint

Date: 2026-07-10

Status: wheel-specific Rust signing/verification and Swift challenge generation/response verification
implemented with a fixed cross-language golden; control framing, lifecycle integration, guest
staging, Python/pip execution, telemetry, and behavioral detection are not implemented by this
checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Authenticated Transport Checkpoint](artifact-native-wheel-authenticated-transport-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Streaming Transport Checkpoint](artifact-native-wheel-guest-streaming-transport-checkpoint-2026-07-10.md)
- [Artifact-Native npm Guest Authentication Checkpoint](artifact-native-npm-guest-authentication-checkpoint-2026-07-10.md)

## Outcome

The wheel path now has a separate challenge/response authentication contract:

- `whoathere.wheel_guest_auth_challenge.v1`;
- `whoathere.wheel_guest_auth_response.v1`; and
- `whoathere.wheel_guest_auth.response_signature.v1`.

The helper-generated challenge binds a fresh 256-bit nonce, complete wheel execution-binding
digest, wheel run-spec digest, disposable-clone binding, and the measured guest Ed25519 public-key
digest. The guest response binds the challenge digest, execution and run-spec digests, clone
binding, measured wheel supervisor, measured fixed wheel runner, and dedicated package UID/GID.

Rust strictly decodes the canonical challenge, signs the response with the measured guest key, and
strictly verifies the complete response. Swift generates the identical canonical challenge and
verifies the Rust Ed25519 response against the expected wheel prelude and backend identity.

The signing seed is accepted by value and zeroized after constructing the signing key. The raw
nonce is omitted from debug output; only its digest is rendered.

## Clone binding

The Swift wheel clone binding uses a wheel-specific domain and commits to:

- stopped-base generation identity;
- unique run identifier;
- cloned disk digest; and
- cloned auxiliary-storage digest.

Changing the run or disk changes the binding. A future lifecycle adapter must derive this value
only from locked and reverified clone state before it issues the guest challenge.

## Ecosystem separation

The wheel challenge/response schemas and signature domain are distinct from npm. A challenge whose
schema is changed to the npm value fails wheel decoding, and an npm-domain signature cannot verify
as a wheel response. This prevents a valid npm guest response from being replayed as authority for
a wheel session.

The wheel response additionally binds the Python/pip run spec indirectly through its complete
run-spec and execution-binding digests. It never accepts Node/npm measurements or an npm guest
protocol identity.

## Fail-closed limits

Challenges and responses are capped at 16 KiB, require canonical JSON and closed key sets, and
require canonical lowercase SHA-256 and signature encodings. Verification fails for:

- stale or different nonces;
- wrong execution, run-spec, or clone bindings;
- wrong or weak public keys;
- changed supervisor, runner, UID, or GID claims;
- noncanonical, unknown, missing, or cross-ecosystem fields; and
- any signature mutation.

Authentication emits no verdict, admission decision, command, artifact path, sync-back option, or
execution authority. Passing authentication only proves the measured guest endpoint answered the
specific challenge with the expected identity claims.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel Mac integration tests | 7 passed, 0 failed |
| `whoathere-macos-vm` tests | 35 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 706 passed, 0 failed |
| Swift helper core tests | 41 passed, 0 failed |
| Swift release build | passed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |

The fixed Rust/Swift golden proves byte-identical JCS challenge generation and successful Swift
verification of the Rust signature. Negative tests cover npm-schema substitution, nonce replay,
claim forgery, signature mutation, signing-key substitution, public-key substitution, and clone
rebinding across run and disk identity.

All inputs were inert generated values. No restricted sample, public registry, network, cloud Mac,
VM, VSOCK device, Python process, pip process, package import, console entry point, or
package-controlled code was used.

## Open gates

This checkpoint defines the authentication primitive; it does not yet prove session ordering. The
next required work is:

1. add wheel-specific bounded control framing for challenge, response, and staging receipt;
2. require successful authentication before constructing `WheelGuestSubmissionForwarder`;
3. stage the exact wheel as an exclusive read-only `artifact.whl`, rehashing the held inode before
   any future launch;
4. sign and verify a wheel-specific `staged_no_execution` receipt;
5. compose authentication, one-pass transfer, receipt, EOF, VM stop, channel termination, and clone
   cleanup into one non-executing session; and
6. only then register a separate helper lifecycle entry requiring the pre-issued host binding.

Package execution and protected behavioral evidence remain later gates. Cloud backends remain
downstream of local detection credibility.
