# Artifact-Native npm Guest Staging Checkpoint

Date: 2026-07-10

Status: non-executing guest staging, close/reopen verification, prelaunch/postrun rehash, and cleanup
implemented; no installed root supervisor, VSOCK listener, authenticated execution authority, VM
boot, package UID process, npm execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Guest Stream Decoder Checkpoint](artifact-native-npm-guest-stream-decoder-checkpoint-2026-07-10.md)

## Outcome

The Rust guest receiver can now be wrapped in a filesystem staging lifecycle suitable for the
future separate root supervisor. It creates one cryptographically random scenario directory and one
fixed `artifact.tgz` with exclusive creation, no symlink following, close-on-exec, and no overwrite.
The streaming decoder writes directly to that descriptor; no artifact-sized memory buffer exists.

The staging API contains no command template, npm call, process spawn, registry setting, sync-back,
guest-file return, or verdict. Its only successful output is a held, read-only artifact identity and
the transport and rehash observations needed by later evidence reconstruction.

## Staging and handoff posture

The staging policy is created for the current supervisor UID and requires a distinct, nonzero
package UID. The selected absolute staging root must already be a real directory owned by that
supervisor with no group/other write permission. Production supervisor wiring must select the fixed
root-owned guest staging root; the generic absolute root exists so the same invariant can be tested
without root privileges.

For each frame, staging:

1. creates a random mode-`0700` scenario directory without creating parent directories;
2. opens `artifact.tgz` with create-new, mode `0600`, `O_NOFOLLOW`, and `O_CLOEXEC`;
3. streams and validates the exact `WHOAGST1` frame into the file;
4. calls `fsync`, verifies regular-file type, supervisor ownership, one link, protected mode,
   declared length, and transport digest;
5. changes the artifact to mode `0444`, calls `fsync` again, and closes the writer;
6. changes the root-owned scenario directory to mode `0711`, allowing the future unprivileged
   package process to traverse but not list or modify it;
7. reopens the artifact read-only with `O_NOFOLLOW` and `O_CLOEXEC`;
8. requires descriptor/path device and inode equality, one link, exact read-only mode, ownership,
   length, and SHA-256; and
9. retains that read descriptor as the identity anchor for all later checks.

A receiver, sync, metadata, permission, reopen, or rehash failure removes the partial artifact and
scenario directory. No successful staging observation is returned.

## Prelaunch, postrun, and cleanup

`verify_prelaunch` and `verify_postrun` independently compare the held descriptor and current path,
then rehash from the descriptor and restore its offset. Both require the original device, inode,
owner, link count, mode, length, and digest. A path replacement therefore fails even if replacement
bytes have the same length and digest.

Cleanup closes the held descriptor before removing the artifact and scenario directory and then
requires path absence. An unexpected residual member or deletion error remains an explicit cleanup
failure; after the residue is handled, cleanup can be retried. Drop performs only a final
best-effort attempt and does not turn a reported failure into success.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Rust Mac backend unit/integration tests with all targets | 20 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 686 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting and `git diff --check` | passed |

Tests prove exact read-only staging, one-link and owner/mode posture, transport identity retention,
prelaunch and postrun descriptor rehash equality, successful descriptor-close and path-absence
cleanup, partial-file cleanup on mutated transport, same-length path replacement detection, visible
cleanup failure with unexpected residue, and successful cleanup retry.

All inputs were repository-generated inert tarballs under temporary local directories. No installed
guest supervisor, cloud Mac, VM, VSOCK connection, package UID process, npm process, network,
package registry, or restricted sample was used.

## Open gates

The next landing must package this code as a separate root-owned guest supervisor, hardcode and
validate the protected staging root and package UID from the measured base receipt, accept only the
dedicated VSOCK port, and return a bounded transport/staging receipt. It must still stop before npm.
Host-side expected-binding authentication and bounded VM start/stop remain prerequisites for any
end-to-end invocation.

Real-malware execution remains outside this goal's authorization.
