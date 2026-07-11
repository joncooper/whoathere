# Artifact-Native Wheel Guest Control Framing Checkpoint

Date: 2026-07-10

Status: wheel-specific bounded Rust and Swift control framing implemented for authentication and
staging messages; lifecycle composition, guest staging, signed staging receipt, Python/pip
execution, telemetry, and behavioral detection are not implemented by this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Guest Authentication Checkpoint](artifact-native-wheel-guest-authentication-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Streaming Transport Checkpoint](artifact-native-wheel-guest-streaming-transport-checkpoint-2026-07-10.md)

## Outcome

The wheel guest session now has a distinct binary control domain, `WHOWCTL1`, with typed frames for:

1. authentication challenge;
2. authentication response; and
3. staging receipt.

Each frame is `magic[8] | version:u16 | type:u16 | body_len:u32 | body`, with network-byte-order
integers, a 64 KiB body ceiling, exact-length reads, and an explicit terminal EOF check. Rust and
Swift implement the same frame values and strict parsing behavior.

The transport does not infer message type from JSON and does not accept an out-of-order frame as
the expected type. Unsupported frame values, empty or oversized bodies, truncated prefixes or
bodies, trailing data, descriptor errors, and bounded Swift socket deadlines all fail closed.

## Ecosystem separation

The npm control domain remains `WHOACTL1`. Both Rust and Swift wheel readers reject an npm control
frame at the magic boundary. A protocol error terminates that logical session; tests use a new
connection for any subsequent exchange rather than attempting to resynchronize attacker-controlled
bytes.

This separation complements the wheel-specific challenge/response schemas, signature domain, and
artifact-stream magic. An npm challenge, response, staging receipt, or stream cannot be substituted
into a wheel session by changing only its JSON fields.

## Structural no-sync posture

The wheel frame-type enum is closed to challenge, response, and staging receipt. There is no command,
sync-back, output-copy, verdict, admission, arbitrary extension, or execution message. Adding any
future frame type requires a versioned code change in both strict decoders.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel Mac integration tests | 8 passed, 0 failed |
| `whoathere-macos-vm` tests | 36 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 707 passed, 0 failed |
| Swift helper core tests | 43 passed, 0 failed |
| Swift release build | passed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |

Tests cover all three ordered frame types, fragmented reads, exact bodies, explicit EOF, npm-magic
rejection, wrong-type rejection, empty-body limits, truncation, and bounded idle-socket timeout.

All bodies were inert generated data. No restricted sample, public registry, network, cloud Mac,
VM, VSOCK device, Python process, pip process, import, console entry point, or package-controlled
code was used.

## Open gates

The next landing must use these frames to enforce the actual session order:

1. issue and verify the wheel auth challenge/response before artifact forwarding;
2. stage the exact `WHOWGST1` wheel as a read-only held `artifact.whl` inode;
3. rehash and sign a wheel-specific `staged_no_execution` receipt;
4. require the receipt and control EOF before declaring a non-executing session complete; and
5. compose failure cleanup with VM stop, channel termination, and clone deletion.

No helper command or package execution path is enabled by this checkpoint. Cloud backends remain
downstream of local detection credibility.
