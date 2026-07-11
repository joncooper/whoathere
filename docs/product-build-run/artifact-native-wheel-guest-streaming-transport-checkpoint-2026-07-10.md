# Artifact-Native Wheel Guest Streaming Transport Checkpoint

Date: 2026-07-10

Status: wheel-specific helper-to-guest streaming frame and strict Rust guest decoder implemented;
helper command/lifecycle registration, guest authentication, guest staging, Python/pip execution,
telemetry, and behavioral detection are not implemented by this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Authenticated Transport Checkpoint](artifact-native-wheel-authenticated-transport-checkpoint-2026-07-10.md)
- [Artifact-Native npm Guest Streaming Transport Checkpoint](artifact-native-npm-guest-streaming-transport-checkpoint-2026-07-10.md)

## Outcome

The helper core can now forward one already validated wheel submission to a future authenticated
guest VSOCK connection without buffering a second complete copy. It changes only the transport
domain magic from the host/helper `WHOAWHE1` value to the wheel guest value `WHOWGST1`; the version,
frame type, canonical header, declared length, artifact digest, and exact raw wheel bytes remain
unchanged.

`WheelGuestSubmissionForwarder` is single-use. It writes the fixed prefix and canonical header,
streams each artifact chunk directly from `WheelRunSubmissionReader`, and closes the socket write
side after the exact frame. A write failure also closes the write side and fails the operation.

The Rust guest-side reference decoder accepts only `WHOWGST1`. It incrementally reads a bounded
prefix and header, strictly reconstructs the wheel run spec, writes artifact chunks directly to a
caller-owned sink, checks the complete SHA-256 and length, requires transport EOF, and returns only
the validated wheel identities and measurements. The caller must discard its sink after every
error.

This is a transport contract and unit-tested socket path. No production helper command currently
constructs the forwarder, no Virtualization.framework VM was booted, and no VSOCK connection was
opened during this checkpoint.

## Ecosystem and authority boundaries

The wheel guest magic is distinct from both:

- the wheel host/helper frame, `WHOAWHE1`; and
- the npm helper/guest frame, `WHOAGST1`.

The Rust wheel guest decoder rejects both other values before reading or writing artifact bytes.
The existing npm decoder remains unchanged and does not accept `WHOWGST1`.

As on the npm path, the guest stream checks the challenge and execution binding for internal
consistency but does not independently establish who issued the challenge. A lifecycle caller must
authenticate the measured wheel guest and bind that session to the pre-issued wheel execution
binding before constructing the forwarder. This checkpoint deliberately does not provide an
unauthenticated shortcut around that ordering.

## Structural no-sync posture

The wheel guest prefix, forwarder, decoder, and observation contain no sync-back field, output path,
arbitrary command, or returned artifact channel. Unknown fields in the retained canonical wheel
header continue to fail strict decoding. The forwarder only writes the one inbound wheel frame and
then closes its write side.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel Mac integration tests | 6 passed, 0 failed |
| `whoathere-macos-vm` tests | 34 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 705 passed, 0 failed |
| Swift helper core tests | 38 passed, 0 failed |
| Swift release build | passed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |

Rust tests prove fragmented-read tolerance, exact streamed bytes, canonical header preservation,
artifact digest and length agreement, host-wheel/npm-guest domain rejection, mutation rejection,
truncation rejection, and trailing-data rejection. Swift socket-pair tests prove exact byte
preservation, write-side EOF, host-parser equivalence after restoring only the magic, single-use
enforcement, and fail-closed behavior when the peer is unavailable.

All bytes were inert repository-generated wheel fixtures. No restricted sample, package registry,
network, cloud Mac, VM, VSOCK device, Python process, pip process, import, console entry point, or
package-controlled code was used.

## Open gates

The next wheel-specific landing must:

1. define and verify a wheel guest-auth challenge/response bound to the measured Python/pip run
   spec, clone identity, supervisor, runner, public key, and package account;
2. add a wheel staging path that creates an exclusive private directory, writes `artifact.whl`,
   verifies length/digest/inode/mode, and removes it on every failure;
3. return a signed, wheel-specific `staged_no_execution` receipt;
4. compose authentication, streaming, staging receipt, EOF, VM stop, channel termination, and clone
   deletion into one non-executing wheel session; and
5. only then register a separate wheel helper command that requires a pre-issued binding and the
   existing zero-NIC, one-boot, clone-only lifecycle.

Package execution and behavioral evidence remain later gates. Cloud backends remain downstream of
local detection credibility.
