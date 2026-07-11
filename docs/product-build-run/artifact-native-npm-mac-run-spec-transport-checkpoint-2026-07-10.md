# Artifact-Native npm Mac Run-Spec And Transport Checkpoint

Date: 2026-07-10

Status: strict Rust-side Mac run-spec and binary-submission reference contracts implemented; no
Swift helper, VSOCK, APFS clone, VM boot, guest receipt, package execution, or dynamic-evidence claim

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Scenario Compiler Checkpoint](artifact-native-npm-scenario-compiler-checkpoint-2026-07-10.md)

## Outcome

The Mac adapter can now capability-match one validated backend-neutral npm scenario template to a
closed `MacosArtifactRunSpecV1`. The run spec embeds the complete canonical template and binds the
selected stopped-base generation, base disk, auxiliary storage, post-provisioning receipt, signed
helper, root guest supervisor, runner configuration, APFS clone implementation, Node executable,
npm CLI, and separate artifact-guest protocol identities.

The run spec represents only:

- macOS on arm64;
- an APFS clone with no byte-copy fallback;
- zero configured network devices;
- one boot and one scenario followed by clone destruction; and
- the exact Node and npm versions and digests already required by the template.

A backend whose Node or npm version or digest differs from the template fails capability matching.
The run spec carries no host path, registry target, package script text, arbitrary argv, sync
operation, guest-file return, verdict, or admission authority.

The Rust reference submission codec now emits the planned binary shape:

```text
magic[8] | version:u16 | frame_type:u16 | header_len:u32 |
artifact_len:u64 | artifact_sha256[32] | canonical_header | artifact_bytes
```

All integers use network byte order. The canonical header contains the complete nested run spec,
its digest, the artifact digest and length, the fixed 64 MiB ceiling, and challenge/execution
bindings. Artifact bytes remain raw and are not copied into JSON, hex, base64, argv, or an arbitrary
host-path field. The streaming writer hashes and checks the complete immutable input before writing
the first byte, then writes directly to a caller-provided `Write` sink.

## Binding model

`MacosArtifactSubmissionBindingsV1` accepts a challenge-binding digest and derives the execution
binding from both that digest and the complete run-spec digest. The caller cannot supply an
unrelated execution-binding value. The decoder receives the trusted expected binding, strictly
reconstructs the nested run spec, rederives the execution binding, and requires exact equality.

Consequently, changing the template, backend identity, helper, base, toolchain, challenge, or run
spec changes the execution binding. A frame that updates its nested run spec and recomputes its own
internal digests still fails against the control plane's expected binding.

This is deterministic pre-execution binding, not yet an authenticated challenge authority. Replay,
freshness, signing, durable reservation, and protected key custody remain Landing 4 work.

## Strict decoding

The run-spec decoder caps input before parsing, denies unknown and duplicate fields and trailing
data, requires RFC 8785/JCS byte identity, reparses the complete nested template through the
artifact-scenario decoder, recomputes template and run-spec digests, validates the backend identity,
and repeats Node/npm capability matching.

The binary-frame decoder then:

- validates magic, version, frame type, header length, artifact length, and checked total length;
- rejects short input and all trailing bytes;
- requires the canonical header and complete nested run spec;
- matches the expected challenge/execution binding;
- requires the header, fixed-prefix, run-spec, and actual artifact length and SHA-256 to agree; and
- returns raw artifact bytes only from the bounded reference decoder.

The decoder used in Rust tests holds the bounded artifact in memory so tests can inspect exact
round trips. The production Swift helper must implement the plan's incremental read/hash/write
path and must not create a second full artifact copy. This checkpoint does not claim that helper
behavior exists.

## Structural no-sync posture

The new Mac backend identity, capability, run-spec, submission-binding, canonical-header, frame, and
decoder types have no sync or output-copy field. The nested template has the same structural
property. Unknown `sync_back` fields fail strict decoding at either layer.

The legacy persistent project VM and its project sync protocol remain separate. No code in this
checkpoint invokes the legacy helper, accepts its result schema, or exposes its sync implementation.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| New Mac run-spec and binary-submission integration tests | 4 passed, 0 failed |
| Artifact-scenario compiler integration tests | 6 passed, 0 failed |
| Existing macOS VM policy unit tests | 13 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 683 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |
| `git diff --check` | passed |

The new tests cover exact nested-template/run-spec reconstruction, zero-NIC and one-clone policy,
backend toolchain mismatch, noncanonical/unknown/duplicate run-spec rejection, raw binary round trip,
size-prefix ceiling enforcement, pre-write size/digest failure, truncation, trailing data, payload
and prefix mutation, unknown header fields, wrong challenge, and a forged helper/run spec that
recomputes its internal identities but cannot match the expected execution binding.

All artifacts were repository-generated inert fixtures. No helper, VM, npm process, cloud Mac, or
restricted sample was used.

## Open gates

This is an interface checkpoint, not S2 or S3 completion. The following remain open:

- a separate Swift `artifact-run` command and streaming stdin parser for the same vectors;
- strict helper-to-guest VSOCK framing on a new port and protocol;
- stopped-base locking and independently verified APFS `clonefile` semantics;
- a Virtualization.framework configuration with `networkDevices = []` and no NAT fallback;
- unconditional bounded VM stop, channel closure, clone deletion, and path-absence verification;
- a separate root guest supervisor, exact guest staging and three rehash points;
- fixed-argv npm execution under the measured unprivileged UID/GID;
- protected process/listener/sensor observations and authenticated evidence; and
- local and second-host inert conformance.

The next action is to implement the non-executing Swift `artifact-run` parser and disposable-VM
lifecycle skeleton. It must parse and validate the Rust frame, prove clone and zero-NIC setup, and
return transport/lifecycle observations without launching npm. Real-malware execution remains
outside this goal's authorization.
