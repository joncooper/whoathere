# Artifact-Native Measured Wheel Launch Checkpoint

Date: 2026-07-10

Status: orchestration-generated measured wheel backend, exact inert submission, unpredictable
short-lived launch authority, private launch handoff, helper consumption, replay rejection, and
pre-boot clone cleanup implemented and self-tested; a valid VM boot remains open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Helper Lifecycle Checkpoint](artifact-native-wheel-helper-lifecycle-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Supervisor Provisioning Checkpoint](artifact-native-wheel-supervisor-provisioning-checkpoint-2026-07-10.md)

## Outcome

`prepare_macos_wheel_launch_v1` now owns the wheel helper's pre-issued authority state. Given a
compiled exact wheel run spec, it:

1. rejects zero, overflowing, or greater-than-15-minute lifetimes;
2. generates independent 256-bit random authority-id and challenge inputs;
3. binds the challenge to the complete run-spec digest and therefore its exact artifact,
   provisioning, helper, runtime, scenario, and policy identities;
4. creates or verifies user-owned mode-`0700` `wheel-authorities/pending` and `consumed`
   directories through no-follow directory descriptors;
5. writes the canonical authority record once with `O_EXCL`, mode `0600`, descriptor verification,
   file `fsync`, and directory `fsync`; and
6. returns the submission header only after that replay state is durable.

The record is the exact schema consumed by the Swift helper. It contains only the authority id,
challenge binding, run-spec digest, artifact digest, issue and expiry times, and schema version.
Package execution, sync-back, allow authority, registry credentials, and artifact bytes are absent.

## Measured inert launch generator

The `measured_inert_wheel_launch` Rust example provides the non-malicious orchestration path needed
for qualification. It independently measures and locks:

- base disk and auxiliary storage;
- hardware model and machine identifier;
- wheel supervisor provisioning receipt and Ed25519 public key; and
- the exact Swift helper executable.

It rejects noncanonical or internally inconsistent receipts, constructs `MacosWheelBackendIdentity`
without operator-authored digests, normalizes a generated inert wheel, compiles its typed
`install_exact_wheel` scenario, persists a two-minute authority, and writes mode-`0600` submission
and launch-manifest files. The launch manifest exposes the authority id and binding digests needed
to invoke `wheel-run`; it structurally records package execution and sync-back as false.

## Executable pre-boot proof

`whoathere-measured-inert-wheel-launch-selftest.sh` creates a temporary measured base whose hardware
metadata is deliberately invalid. It then uses the real Rust generator and real Swift helper to
prove this order:

1. measured backend and exact inert wheel frame are generated;
2. one pending authority exists and no consumed record exists;
3. `wheel-run` atomically moves the authority to consumed state before base/VM acceptance;
4. the helper verifies the measured base and creates an APFS clone;
5. invalid Virtualization.framework metadata fails closed before VM start;
6. the pre-boot clone is removed and its absence verified;
7. output retains `package_execution_enabled: false` and `sync_back_enabled: false`; and
8. replaying the same frame and authority id fails as already consumed.

This is stronger than a parser-only test but intentionally stops before boot, VSOCK, Python, pip,
or package code.

## Verification

The focused gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel backend integration tests | 15 passed, 0 failed |
| Full Rust workspace | 717 passed, 0 failed |
| Swift helper core tests | 53 passed, 0 failed |
| Measured inert wheel launch example | built |
| Measured inert wheel launch self-test | passed |
| Rust formatting | passed |
| Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |

The authority tests additionally prove unique challenge and authority values, exact run-spec and
artifact binding, private file modes, secure directory modes, excessive-lifetime rejection, and
unsafe-state-directory rejection.

No restricted artifact, registry access, public network, cloud Mac, valid VM boot, VSOCK session,
Python process, pip process, package import, console entry point, or malware was used.

## Open gates

The next landing must run this exact handoff against a valid, separately approved inert measured
base and prove VM start, wheel-only VSOCK authentication, exact staging receipt, control EOF, VM
stop, and clone absence. That run must still keep package execution disabled. Only after the
lifecycle proof passes should the fixed offline pip install/import/`.pth`/entry-point runner be
enabled behind a new typed evidence contract.
