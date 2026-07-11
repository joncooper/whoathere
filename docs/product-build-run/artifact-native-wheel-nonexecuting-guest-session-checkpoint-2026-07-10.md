# Artifact-Native Wheel Non-Executing Guest Session Checkpoint

Date: 2026-07-10

Status: wheel-specific host and guest session composition implemented through authentication,
one-pass transfer, staging, signed receipt, EOF, and guest cleanup; helper command/lifecycle and VM
integration, Python/pip execution, telemetry, and behavioral detection are not implemented by this
checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Guest Authentication Checkpoint](artifact-native-wheel-guest-authentication-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Control Framing Checkpoint](artifact-native-wheel-guest-control-framing-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Staging Checkpoint](artifact-native-wheel-guest-staging-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Staging Receipt Checkpoint](artifact-native-wheel-guest-staging-receipt-checkpoint-2026-07-10.md)

## Outcome

The wheel host/helper and guest primitives are now composed into one closed non-executing session.
The only successful order is:

1. compare the parsed submission with the trusted pre-issued challenge-binding digest;
2. send a fresh wheel authentication challenge over `WHOWCTL1`;
3. verify the measured guest's signed authentication response;
4. forward exactly one canonical `WHOWGST1` wheel frame and close the host write side;
5. stage and first-rehash the exact wheel as held read-only `artifact.whl`;
6. bind the staged run spec and backend identity back to the authenticated challenge;
7. construct and sign the wheel-specific `staged_no_execution` receipt;
8. remove and verify removal of the staged wheel and scenario directory;
9. send the receipt only after cleanup succeeds; and
10. verify the receipt and terminal guest control EOF on the host.

The returned host observation contains authenticated identity, exact transport identity, signed
staging evidence, and `packageExecutionEnabled: false`.

## Pre-issued authority boundary

`runNonExecutingWheelGuestSession` requires the trusted expected challenge-binding digest as a
separate argument and compares it before writing an authentication frame or consuming artifact
bytes. A wrong authority value fails immediately; an executable test proves the caller can still
consume the untouched inert artifact afterward.

This closes the earlier internal-consistency limitation at the composed-session boundary. Durable
single-use reservation and replay-state persistence remain helper lifecycle work.

## Guest binding and cleanup behavior

After staging, the guest requires exact agreement among the challenge, canonical wheel header,
complete run spec, execution binding, measured guest public key, supervisor, fixed runner, and
package UID/GID. A rebound challenge still receives its signed authentication response, but the
later header comparison fails, staged state is removed, and no staging receipt is emitted.

The guest derives receipt device/inode and rehash claims only from the verified held staged object.
It removes staged state before writing the receipt. Cleanup failure replaces success with an
explicit failure and suppresses the receipt.

## Structural no-execution and no-sync posture

Neither session implementation has a Python, pip, shell, argv, import, console entry-point,
sync-back, output-copy, verdict, or admission operation. The only control frames remain
authentication challenge, authentication response, and staging receipt. The only artifact flow is
host to guest, after which the host closes its write side.

## Verification

The focused gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel Mac integration tests | 13 passed, 0 failed |
| `whoathere-macos-vm` tests | 41 passed, 0 failed |
| Full Rust workspace | 712 passed, 0 failed |
| Swift helper core tests | 47 passed, 0 failed |
| Swift release build | passed |
| Rust formatting | passed |
| Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |

Rust tests prove full guest ordering, exact-byte staging, cleanup-before-receipt, signed response and
receipt verification, no execution, and challenge/header rebinding rejection with no receipt. Swift
socket-pair tests prove pre-issued authority validation, authentication-before-forwarding, exact
one-pass wheel transfer, signed receipt verification, explicit EOF, and no artifact consumption on
authority failure.

All package bytes and claims were inert generated fixtures. No restricted sample, public registry,
network, cloud Mac, Virtualization.framework VM, VSOCK device, Python process, pip process, import,
console entry point, or package-controlled code was used.

## Open gates

The next landing must integrate this session with a separate wheel helper lifecycle entry that:

1. atomically reserves and consumes the pre-issued authority;
2. verifies and locks a stopped base provisioned with the measured Python/pip wheel supervisor;
3. creates one APFS clone with no copy fallback and zero network devices;
4. authenticates and runs this non-executing session on the wheel VSOCK port;
5. stops the VM, proves channel termination, removes the clone, and verifies absence on every path;
6. emits lifecycle-only observations while package execution remains disabled; and
7. keeps the npm command, schemas, ports, control frames, and guest supervisor distinct.

Package execution and protected behavioral evidence remain later gates. Cloud backends remain
downstream of local detection credibility.
