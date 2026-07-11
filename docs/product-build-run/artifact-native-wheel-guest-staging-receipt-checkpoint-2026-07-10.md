# Artifact-Native Wheel Guest Staging Receipt Checkpoint

Date: 2026-07-10

Status: wheel-specific signed `staged_no_execution` receipt implemented and independently verified
across Rust and Swift; session composition, helper lifecycle, Python/pip execution, telemetry, and
behavioral detection are not implemented by this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Guest Authentication Checkpoint](artifact-native-wheel-guest-authentication-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Staging Checkpoint](artifact-native-wheel-guest-staging-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Control Framing Checkpoint](artifact-native-wheel-guest-control-framing-checkpoint-2026-07-10.md)

## Outcome

The wheel guest can now sign a strict canonical receipt after exact-byte staging and its first
held-inode rehash. The receipt uses:

- schema `whoathere.wheel_guest_staging_receipt.v1`; and
- signature domain `whoathere.wheel_guest_staging_receipt.signature.v1`.

The signed body binds:

- the complete authenticated challenge digest;
- wheel execution-binding, run-spec, and disposable-clone digests;
- exact original wheel SHA-256 and byte length;
- identical first-rehash SHA-256 and length;
- staged device and inode;
- literal filename `artifact.whl`;
- file mode `0444` and scenario-directory mode `0711`;
- dedicated package UID/GID; and
- `status: staged_no_execution` with `package_execution_enabled: false`.

Rust signs and strictly verifies the receipt with the measured guest Ed25519 key. Swift independently
validates the canonical schema, all host-known bindings, fixed posture, numeric encodings, and Rust
signature. A fixed cross-language golden proves the two implementations agree.

## Authority boundary

Device and inode values originate inside the measured guest and are protected by its signature;
the host cannot independently observe those filesystem identifiers. The host does independently
bind the receipt to the authenticated measured guest, exact run spec, execution binding, artifact
digest and length, supervisor, runner, public key, and package account.

Within the guest, the staging implementation obtains device and inode from the held read descriptor
and verifies that the visible `artifact.whl` path still names the same object. A later composed
session must construct receipt claims only from that verified observation, not from caller-provided
numbers.

## Ecosystem and no-execution separation

The schema, signature domain, and literal `.whl` filename are wheel-specific. An npm staging receipt
cannot verify as a wheel receipt. The closed receipt has no sync-back, output-copy, interpreter,
command, verdict, clean, or admission field.

Changing `package_execution_enabled`, the filename, artifact identity, rehash, device/inode,
UID/GID, mode, status, or any binding fails semantic validation or Ed25519 verification.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel Mac integration tests | 11 passed, 0 failed |
| `whoathere-macos-vm` tests | 39 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 710 passed, 0 failed |
| Swift helper core tests | 45 passed, 0 failed |
| Swift release build | passed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |

Tests cover Rust sign/verify, byte-stable cross-language golden verification, execution-enabled
substitution, wrong `.tgz` filename, device/inode mutation, signature mutation, and expected-claim
rebinding.

All values and wheel bytes were inert generated fixtures. No restricted sample, public registry,
network, cloud Mac, VM, VSOCK device, Python process, pip process, import, console entry point, or
package-controlled code was used.

## Open gates

The next landing must compose one non-executing wheel session that:

1. authenticates over `WHOWCTL1` before constructing the artifact forwarder;
2. forwards and stages exactly one `WHOWGST1` wheel;
3. derives receipt claims from the actual first held-inode rehash;
4. returns and verifies the signed staging receipt plus terminal control EOF;
5. cleans staged state on every success or error; and
6. remains coupled to VM stop, channel termination, and clone deletion before helper lifecycle
   integration is considered complete.

Package execution and protected behavioral evidence remain later gates. Cloud backends remain
downstream of local detection credibility.
