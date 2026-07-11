# Artifact-Native Wheel Guest Staging Checkpoint

Date: 2026-07-10

Status: exact wheel guest stream is staged into an exclusive read-only held inode with prelaunch and
postrun rehash plus verified cleanup; signed staging receipt, session composition, helper lifecycle,
Python/pip execution, telemetry, and behavioral detection are not implemented by this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Guest Streaming Transport Checkpoint](artifact-native-wheel-guest-streaming-transport-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Authentication Checkpoint](artifact-native-wheel-guest-authentication-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Guest Control Framing Checkpoint](artifact-native-wheel-guest-control-framing-checkpoint-2026-07-10.md)

## Outcome

The Rust guest boundary can now consume one `WHOWGST1` frame and stage its exact raw wheel bytes as
`artifact.whl` beneath a fresh private scenario directory. The staging path:

- requires an absolute, supervisor-owned root that is not group- or world-writable;
- requires a nonzero package UID different from the supervisor UID;
- creates a random `wheel-scenario-*` directory with exclusive `0700` creation;
- creates `artifact.whl` with `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` and initial `0600` mode;
- incrementally streams and hashes the exact declared wheel bytes;
- syncs the file, changes it to `0444`, syncs again, and changes the directory to `0711`;
- reopens through `O_NOFOLLOW`, records a held read descriptor, device, and inode; and
- requires agreement among descriptor and path type, owner, link count, mode, size, device, inode,
  and SHA-256.

The staged object exposes explicit prelaunch and postrun rehash operations. Both seek and hash the
held descriptor, then revalidate that the visible path still names the same immutable inode. This
is the boundary a future fixed wheel runner must pass immediately before and after package code.

## Failure and cleanup behavior

Any malformed, truncated, mutated, or trailing transport input fails staging and removes the
partial file and scenario directory. `StagedMacosWheelGuestV1` also attempts cleanup on drop.

Explicit cleanup closes the held descriptor, removes only the exact wheel path and scenario
directory, and verifies directory absence. If an attacker replaces or renames the visible path,
verification fails and cleanup reports failure rather than claiming success. Cleanup can be retried
after the conflicting residue is removed.

Paths are redacted from `Debug`; the observation exposes only bound artifact identity, length,
device, inode, phase, and cleanup state.

## Structural no-execution and no-sync posture

Staging only writes and rehashes `artifact.whl`. It has no interpreter, pip, argv, shell, import,
entry-point, result-copy, sync-back, verdict, or admission interface. It cannot make the staged file
writable by the package account and does not invoke the package account.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel Mac integration tests | 10 passed, 0 failed |
| `whoathere-macos-vm` tests | 38 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 709 passed, 0 failed |
| Swift helper core tests (unchanged by this Rust guest slice) | 43 passed, 0 failed |
| Swift release build | passed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |

Tests prove exact `.whl` filename and bytes, `0444` mode, single link, expected length and digest,
stable device/inode across prelaunch and postrun rehash, complete cleanup, mutated-stream cleanup,
path-replacement detection, false-cleanup rejection, and successful cleanup retry.

All wheel bytes were inert repository-generated fixtures. No restricted sample, public registry,
network, cloud Mac, VM, VSOCK device, Python process, pip process, import, console entry point, or
package-controlled code was used.

## Open gates

The next landing must:

1. derive signed staging claims from the authenticated challenge, exact wheel transport, first
   held-inode rehash, and dedicated UID/GID;
2. emit and verify a wheel-specific `staged_no_execution` receipt over `WHOWCTL1`;
3. require authentication before staging and require the verified receipt plus EOF afterward;
4. guarantee staged-object cleanup on every session error; and
5. compose that non-executing session with VM stop, channel termination, and clone deletion.

Package execution and protected behavioral evidence remain later gates. Cloud backends remain
downstream of local detection credibility.
