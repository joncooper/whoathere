# Artifact-Native npm Guest Control Framing Checkpoint

Date: 2026-07-10

Status: bounded typed control frames and host authentication-session primitive implemented in Rust
and Swift; no VSOCK listener wiring, staging receipt schema, guest private-key loading, VM boot,
artifact forwarding in a VM, package execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm Guest Authentication Checkpoint](artifact-native-npm-guest-authentication-checkpoint-2026-07-10.md)
- [Artifact-Native npm Guest Streaming Transport Checkpoint](artifact-native-npm-guest-streaming-transport-checkpoint-2026-07-10.md)

## Outcome

Rust and Swift now implement the same domain-separated `WHOACTL1` control frame. A frame has an
eight-byte magic, version, closed message type, bounded body length, and raw body. The only types are
authentication challenge, authentication response, and staging receipt. The codec does not accept a
generic operation name, argv, path, sync command, or package result.

The Swift helper core also has an authentication-session primitive. It requires the complete locked
base identity to equal the submission's measured backend identity, derives the unique clone binding,
generates the fresh challenge, writes the challenge frame, reads only an authentication-response
frame, and verifies the signed claims with the measured public key. It returns a verified
authentication observation only; it does not invoke the artifact forwarder.

This creates an explicit code boundary: authentication can and must complete before the first
artifact byte is read from the host submission or written to the guest connection.

## Bounded socket behavior

Swift socket reads and writes use absolute monotonic deadlines, `poll`, nonblocking `send`/`recv`,
short-read/write loops, `MSG_NOSIGNAL`, and a 64 KiB global control-body ceiling. A trickle of bytes
does not reset the deadline. Invalid descriptors, wrong magic/version/type, unexpected ordering,
zero or oversized bodies, truncation, timeout, I/O failure, trailing final data, and missing final
EOF are distinct errors.

Rust's generic `Read`/`Write` codec applies the same frame shape, body ceiling, expected-type order,
short-read handling, and explicit final EOF check. Transport EOF is required only after the final
guest receipt; length framing allows the authentication response and later receipt to share the
same guest-to-host stream.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Swift helper authentication, control, protocol, lifecycle, and transport tests | 29 passed, 0 failed |
| Rust Mac backend unit/integration tests with all targets | 22 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 688 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting, production Swift build, and `git diff --check` | passed |

Tests cover bidirectional typed frame round trips, one-byte fragmented Rust reads, unexpected type,
truncation, bounded idle timeout, explicit final EOF, trailing final data, and a complete local
socket-pair authentication session using a measured base and unique APFS clone. Existing
cross-language Ed25519, raw artifact, staging, rehash, and cleanup tests remain green.

All control bodies and keys were inert test fixtures over Unix socket pairs or in-memory streams.
No production key, cloud Mac, VM, VSOCK connection, package process, npm process, network, registry,
or restricted sample was used.

## Open gates

The next landing must define and cross-validate the non-executing staging receipt, then compose the
ordered connection state machine: challenge, signed response, raw artifact frame, staging receipt,
guest write-side EOF, host channel close, VM stop, and clone cleanup. Only after this state machine
passes fault injection should it be connected to a real VSOCK listener and inert VM boot.

Real-malware execution remains outside this goal's authorization.
