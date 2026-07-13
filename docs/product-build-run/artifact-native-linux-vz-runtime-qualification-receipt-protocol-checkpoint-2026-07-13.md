# Artifact-Native Linux VZ Runtime-Qualification Receipt Protocol Checkpoint

Date: 2026-07-13

Status: a strict guest-decodable request, bounded one-shot transport, and signed exact-claim
runtime-qualification receipt are implemented; the guest agent and qualification overlay do not
yet exist, no package-runtime VM has booted, and the candidate remains unqualified

## Outcome

The runtime-qualification protocol now has a closed guest-side interpretation instead of relying
on host construction alone. The canonical request can be structurally decoded without trusted
host objects while preserving its exact bytes and digest. It rejects unknown fields,
noncanonical JSON, empty or reused identities, malformed decimal values, a wrong fixed report,
open-ended policies, elevated authority, package execution, and any sync-back path.

The transport permits exactly one bounded canonical request and one bounded three-part response:

- the exact fixed non-executing probe report;
- the protected process-evidence payload; and
- the domain-separated Ed25519 guest receipt.

Distinct request and response magics, fixed-width lengths, per-part ceilings, exact frame lengths,
and trailing-byte rejection prevent cross-protocol or concatenated-message interpretation.

## Signed receipt contract

The guest receipt binds the canonical qualification request and repeats the exact identities for:

- the qualified telemetry record, measured backend, requirements, conformance set, kernel,
  qualified initramfs, signer, protected sensor, and evidence key;
- the runtime-qualification initramfs, guest agent, guest init, and module bundle;
- the candidate rootfs bytes and byte length, runtime manifest, and package runner;
- the fresh request challenge and unique clone binding; and
- the fixed rootfs device, filesystem type and UUID, read-only mount options, unprivileged
  UID/GID, runner path, closed argument, and successful exit status.

Receipt construction accepts only the exact probe-report digest and exact candidate-rootfs digest.
Its process claim must be observation-complete and healthy, with no truncation or dropped events,
complete descendant teardown, and precisely the protected `fork`, `exec`, and `exit` sequence.
The receipt states that package capabilities and public-network reachability were absent and that
execution authority, package execution, and sync-back were all false.

The signature domain length-prefixes both the exact canonical request and the unsigned receipt.
Verification checks the request-bound evidence public-key digest, rejects weak keys, requires a
canonical closed receipt, independently reconstructs every expected field, and only then verifies
the Ed25519 signature. A valid receipt still exposes false package-execution and sync-back
authority; it is evidence for qualifying an inert runtime composition, not a package grant.

## Verification

The complete `whoathere-macos-vm` crate passed 180 tests, including:

- strict request structure, exact binding, and authority-elevation rejection;
- request/response framing, truncation, wrong-magic, trailing-byte, and empty-part rejection;
- successful signing and verification of the exact fixed probe claims; and
- rejection of an elevated or rebound runtime-qualification request and receipt.

Rust formatting was clean and Clippy passed across all crate targets with warnings denied.

## Claim boundary

This checkpoint did not build a Linux guest agent, build or sign a qualification initramfs, boot a
VM, attach or mount the candidate rootfs, run the inert probe, produce physical evidence, qualify a
runtime, issue a one-use package grant, execute npm or pip, process a package artifact, or handle
malware. It does not improve the July malicious-package detection score.

Real malware remains restricted to the approved cloud Mac lab workflow. Local work remains code,
unit tests, deterministic image construction, and inert fixtures only.

## Next gate

Implement the minimal Linux guest agent and deterministic qualification overlay. The agent must
accept only this request domain, verify its measured components, stream-hash the exact root block
device, validate and mount it read-only with `nodev,nosuid`, invoke the already-qualified sensor on
the fixed probe as UID/GID 65534, sign the exact receipt, close the channel, unmount, and terminate.
Then independently verify two byte-identical overlay builds before one inert physical run on the
approved cloud Mac.
