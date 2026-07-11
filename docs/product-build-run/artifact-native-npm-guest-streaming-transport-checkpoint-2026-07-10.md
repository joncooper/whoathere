# Artifact-Native npm Guest Streaming Transport Checkpoint

Date: 2026-07-10

Status: single-pass host submission reader and exact helper-to-guest byte forwarder implemented;
no authenticated execution authority, VSOCK listener wiring, guest decoder/staging, VM boot, package
execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Swift Transport Parser Checkpoint](artifact-native-npm-swift-transport-parser-checkpoint-2026-07-10.md)
- [Artifact-Native npm Disposable Lifecycle Primitives Checkpoint](artifact-native-npm-disposable-lifecycle-primitives-checkpoint-2026-07-10.md)

## Outcome

The Swift artifact parser now separates the bounded canonical prelude from the raw artifact body.
`beginArtifactSubmission` consumes and validates only the fixed prefix and complete nested header,
then returns a single-use reader. The caller can inspect the exact run spec, execution binding,
artifact digest/length, scenario, and measured backend identity before consuming any package byte.

This ordering is required for the intended production sequence: authenticate the pre-issued
binding, verify the stopped base, create and configure the zero-NIC clone, establish the dedicated
guest channel, and only then read the artifact body. The current command still uses the compatibility
wrapper that consumes and validates the complete frame and returns exit 78; it does not call any
lifecycle or guest transport primitive.

## Single-pass body

`ArtifactRunSubmissionReader.consumeArtifact` reads at most 64 KiB at a time, updates the helper's
SHA-256, and gives the same chunk to one caller-provided sink. It requires the exact declared length,
digest, and EOF, and cannot be called twice. The default sink discards bytes for the current
non-executing parser path.

The split does not weaken validation: the prelude still requires canonical closed JSON and every
nested digest, while the completed transport observation is unavailable until the raw body and EOF
checks pass. A downstream sink may receive bytes before the final digest check, so the guest must
stage and independently verify the complete artifact before any launch. That is an explicit next
gate, not an execution claim.

## Helper-to-guest framing

`ArtifactGuestSubmissionForwarder` writes a distinct `WHOAGST1` magic, version and frame type, the
same bounded lengths and raw SHA-256, the exact already-validated canonical header, and the raw body
chunks to a connected socket descriptor. It uses `MSG_NOSIGNAL`, handles interrupted short writes,
and performs a write-side shutdown only after host digest and EOF validation succeed. On any error
it shuts down the write side so a guest sees truncation or an invalid digest and cannot wait for or
interpret additional package bytes.

The guest frame is byte-for-byte identical to the Rust-to-Swift submission after the domain-separate
eight-byte magic. Artifact bytes are not stored on the host, encoded, placed in argv or JSON, or
represented by an arbitrary host path. The dedicated forwarder contains no sync or guest-file
return operation.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Swift helper protocol, lifecycle, guest-forwarder, and existing core tests | 23 passed, 0 failed |
| Production Swift helper build | passed |
| Rust-to-Swift inert frame interoperability after reader split | parsed and blocked as designed, exit 78 |
| `git diff --check` | passed |

Tests prove prelude-before-body ordering, exact single-pass chunk forwarding, second-consumption
rejection, canonical-header preservation, raw-artifact preservation, write-side EOF, reparsing after
only the domain magic is restored, and peer-close failure without `SIGPIPE`. Existing tests continue
to cover corruption, truncation, trailing bytes, unknown fields, binding recomputation, APFS clones,
zero-NIC configuration facts, and cleanup.

All inputs were small repository-generated inert fixtures over local pipes and Unix socket pairs.
No cloud Mac, VM, VSOCK connection, guest code, npm process, network, package registry, or restricted
sample was used.

## Open gates

The next transport landing is a separate root guest supervisor with a streaming `WHOAGST1` decoder.
It must write with exclusive no-follow semantics, enforce the same ceiling, require socket EOF after
the declared body, fsync and close, reopen and rehash a regular root-owned file, and remain unable to
launch npm. Only then should the host VSOCK listener and bounded VM start/stop path be wired.

Authenticated expected-binding consumption remains mandatory before any clone or VM action. Real
malware execution remains outside this goal's authorization.
