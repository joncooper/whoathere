# Artifact-Native npm Guest Stream Decoder Checkpoint

Date: 2026-07-10

Status: bounded Rust guest-frame decoder implemented; no secure guest file staging, VSOCK listener,
authenticated execution authority, VM boot, npm execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Guest Streaming Transport Checkpoint](artifact-native-npm-guest-streaming-transport-checkpoint-2026-07-10.md)

## Outcome

`whoathere-macos-vm` now contains the streaming receiver for the Swift helper's `WHOAGST1` frame.
The receiver incrementally reads from any `Read` implementation and writes artifact chunks to a
caller-owned `Write` sink. It allocates only the bounded canonical header and one 64 KiB body
buffer; it never returns or retains an artifact byte buffer.

The host submission and guest submission use domain-separated magic values and the same strict
header implementation. Refactoring the shared header validator keeps Rust's trusted expected-binding
check on the host side while allowing the dedicated helper-to-guest channel to validate internal
challenge/run-spec consistency. The latter is not a substitute for host authority: the host must
authenticate and consume its expected binding before it creates the channel.

## Receiver contract

`stream_macos_artifact_guest_submission_v1` requires:

- exact `WHOAGST1` magic, version, frame type, header length, artifact length, and raw digest;
- the same header and artifact ceilings as the host submission;
- canonical closed JSON with a complete strictly validated Mac run spec and scenario template;
- exact run-spec, execution-binding, artifact-digest, and artifact-length agreement;
- exactly the declared artifact body, hashed while streaming; and
- transport EOF immediately after the body.

Short reads are normal and supported; interrupted reads are retried. Truncation, wrong transport
domain, unsupported versions/types, noncanonical or unknown header fields, nested binding failure,
body mutation, sink I/O failure, and trailing bytes all return typed fail-closed errors. The caller
must discard its sink on every error because bytes are necessarily written before the final digest
and EOF are known. A successful return contains only the validated header identity and observed
digest/length.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Rust Mac backend unit/integration tests with all targets | 18 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 684 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting and `git diff --check` | passed |

The new integration test feeds the decoder three bytes at a time, proves exact canonical-header and
raw-artifact recovery, and checks the resulting run-spec and digest identities. It also proves that
the host `WHOAART1` domain is rejected before sink writes, while mutation, truncation, and trailing
data fail after bounded partial staging and cannot produce a successful observation.

All inputs were repository-generated inert tarballs and in-memory streams. No guest filesystem,
cloud Mac, VM, VSOCK connection, npm process, network, package registry, or restricted sample was
used.

## Open gates

The next guest landing must wrap this decoder in a separate root supervisor that creates an
exclusive no-follow staging file in a protected per-scenario directory, fsyncs and closes it,
reopens and proves regular-file identity, length, and digest, changes it to a read-only posture for
the package UID, and repeats the same descriptor/path proof before and after the eventual npm run.
The supervisor must discard partial files on every receiver error and remain unable to launch npm.

Real-malware execution remains outside this goal's authorization.
