# Artifact-Native npm Swift Transport Parser Checkpoint

Date: 2026-07-10

Status: strict, streaming, non-executing Swift artifact-submission parser implemented and
cross-language checked; no authenticated challenge authority, APFS clone, VM boot, guest transfer,
npm execution, dynamic telemetry, behavioral detection, or admission claim

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Mac Run-Spec And Transport Checkpoint](artifact-native-npm-mac-run-spec-transport-checkpoint-2026-07-10.md)

## Outcome

The packaged macOS helper now recognizes a separate `artifact-run` invocation with its own narrow
option type. This path accepts only `--execute`, `--json`, and an optional `--state-dir`. It cannot
parse or inherit legacy detonation tool, project-payload, arbitrary-argument, or sync-back options.
Unknown options fail before stdin is read.

With `--execute`, the helper consumes the Rust artifact-submission frame from stdin. It validates
the bounded canonical header, incrementally reads and hashes the exact raw artifact, rejects all
trailing data, and returns only a bounded transport observation. It does not write the artifact to
disk, create a VM, invoke npm, or enable package execution. After a valid parse it deliberately
returns exit 78 and `artifact_run_disposable_vm_lifecycle_not_implemented`; invalid input returns a
sanitized protocol error. Omitting `--execute` also blocks without reading or executing anything.

The current result advances the host/helper boundary of S2. It does not complete S2 or begin an S3
package-execution claim.

## Closed Swift decoder

The parser enforces the 56-byte binary prefix and the same 576 KiB header and 64 MiB artifact caps
as the Rust reference codec. It requires exact magic, version, frame type, positive bounded lengths,
and agreement among the prefix, header, nested run spec, nested template, and observed artifact
SHA-256 and length.

The canonical JSON validator uses closed key sets throughout the header, Mac run spec, backend
identity, artifact template, identities, subject, package identity, runtime profile, empty
dependency closure, scenario, lifecycle hooks, limits, and required evidence. It recomputes the
canonical runtime-profile, empty-closure, template, run-spec, command-template, guest-protocol, and
execution-binding digests. It also rechecks:

- npm, macOS, and arm64 first-slice scope;
- zero configured network devices;
- APFS clone required with no copy fallback;
- one boot, one scenario, then clone destruction;
- dedicated unprivileged package execution posture;
- exact Node and npm version/digest agreement between template and backend;
- the canonical artifact CAS key and empty dependency closure;
- ordered, unique, qualified install-time lifecycle hooks; and
- the exact required-evidence set and positive resource ceilings.

Artifact bytes are never encoded into JSON, argv, a path field, or the helper result. The streaming
read keeps only the bounded canonical header and one 64 KiB artifact chunk at a time.

## Cross-language check

A new Rust example builds a deterministic inert npm tarball in memory, normalizes it, compiles the
closed `CI=false` scenario, selects the measured Mac backend, derives the run spec and submission
bindings, and writes the production binary frame to stdout. The frame was piped into the built
Swift helper.

The Swift helper accepted the Rust JCS and binary encoding, matched the 205-byte artifact and its
SHA-256, matched every nested digest, reported `transport_verified: true`, kept
`vm_execution_enabled` and `package_execution_enabled` false, and returned the expected fail-closed
exit 78. This is a protocol interoperability check, not a VM or npm run.

## Challenge-authority boundary

The parser proves that the challenge digest, run-spec digest, and derived execution-binding digest
are internally self-consistent. It does not yet know which challenge an authenticated control-plane
authority issued for this invocation. A same-user sender can therefore replace the challenge and
rederive a self-consistent execution binding unless a later authority check compares the parsed
binding with the pre-issued expected value.

The Swift test suite preserves this limitation as an explicit executable test instead of implying
that internal hashing provides authentication. VM creation and package execution must remain
disabled until the helper receives and atomically consumes an authenticated, fresh expected binding
or an equivalent protected capability. Replay prevention, durable reservation, and protected key
custody remain Landing 4 work.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Swift helper protocol and existing core tests | 17 passed, 0 failed |
| Rust Mac backend/detonation tests with all targets | 25 passed, 0 failed |
| Rust-to-Swift inert frame interoperability | parsed and blocked as designed, exit 78 |
| Full Rust workspace tests, including compile-fail doc tests | 683 passed, 0 failed |
| Workspace Clippy with warnings denied, including the emitter example | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |
| `git diff --check` | passed |

Swift tests cover the separate no-sync option grammar, a complete valid canonical frame,
truncation, trailing bytes, artifact mutation, unknown header fields, and the unauthenticated
self-consistent challenge-rebinding boundary. Rust coverage continues to exercise malformed nested
run specs, unknown and duplicate fields, noncanonical wire, size ceilings, and trusted expected
binding mismatch.

All bytes were repository-generated inert fixtures. No real model, cloud Mac, VM, npm process,
network, live package registry, or restricted sample was used.

## Open gates

The helper still needs a disposable-lifecycle implementation that:

- verifies an authenticated expected execution binding before any mutable action;
- locks and revalidates the stopped measured base;
- creates exactly one APFS clone and proves clone semantics without a copy fallback;
- constructs a Virtualization.framework configuration with `networkDevices = []`;
- uses a separate strict artifact VSOCK protocol and incremental guest staging;
- reports lifecycle-only observations before package execution is introduced; and
- unconditionally stops the VM, closes channels, deletes the clone, and verifies path absence.

Only after those lifecycle invariants pass should the root guest supervisor and fixed-argv,
unprivileged npm execution path be added. Real-malware execution remains outside this goal's
authorization.
