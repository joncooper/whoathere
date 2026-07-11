# Artifact-Native Wheel Helper Lifecycle Checkpoint

Date: 2026-07-10

Status: wheel-specific helper lifecycle, single-use launch authority, measured-base verification,
APFS clone policy, zero-network VM configuration, VSOCK session wiring, terminal cleanup policy, and
guest supervisor executables implemented; stopped-base provisioning automation, an actual
Virtualization.framework launch, Python/pip execution, protected telemetry, and behavioral verdicts
remain open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Non-Executing Guest Session Checkpoint](artifact-native-wheel-nonexecuting-guest-session-checkpoint-2026-07-10.md)

## Outcome

The macOS helper now has a distinct `wheel-run` entry whose successful non-executing order is:

1. parse and structurally validate only the canonical wheel prefix and header from standard input;
2. atomically move the named pre-issued authority from `pending` to durable `consumed` state;
3. validate that the consumed authority binds the exact challenge, run spec, and wheel digest;
4. verify and lock the stopped measured base, helper, wheel supervisor public key, and
   Python/pip-specific provisioning receipt;
5. create one APFS clone with no byte-copy fallback;
6. construct a VM with zero network devices, one VSOCK device, no guest-tools attachment, and the
   wheel-only port `47080`;
7. accept at most one connection on that port and run the authenticated non-executing wheel session;
8. remove the listener, stop the VM, and require proof that the guest channel terminated;
9. authorize clone deletion only after both VM stop and channel termination are proven; and
10. emit the wheel-only lifecycle schema with package execution and sync-back both false.

The helper never derives launch authority from the submitted wheel header alone. A missing,
expired, malformed, rebound, or replayed authority fails closed. Every attempted authority use is
spent before semantic acceptance, so correcting a rejected record cannot turn the same authority id
into a second attempt.

## Wheel-only measured guest

The Rust crate now builds separate `whoathere-wheel-supervisor` and
`whoathere-wheel-supervisor-keygen` targets. Their compile-time binary identity selects wheel-only:

- config schema `whoathere.wheel_guest_supervisor_config.v1`;
- config and Ed25519 seed paths;
- public-key output name;
- staging root `/var/db/whoathere/wheel-staging`;
- VSOCK port `47080`;
- wheel control, authentication, transport, staging, and receipt types; and
- wheel-specific failure reasons.

The npm artifact supervisor remains on port `47079` with its existing config, key names, staging
root, and protocol. Cross-ecosystem transport and control frames remain mutually rejected.

The host accepts a wheel base only when its canonical
`whoathere.wheel_supervisor_provisioning.v1` receipt binds the measured supervisor, Ed25519 public
key, fixed runner config, Python executable, pip CLI, clone implementation, guest protocol, UID/GID,
CPU/memory limits, port, and the structural false values for package execution and sync-back.

## Cleanup and failure posture

Authority replay state remains persisted even when a later base, clone, VM, guest, or receipt check
fails. Before VM start, a created clone is removed on error. After start, clone deletion is withheld
unless both VM stop and guest-channel termination are proven; the failure report identifies the
retained clone condition. A successful report requires authenticated staging evidence, terminal
guest EOF, VM stop, and verified clone absence.

## Verification

The focused implementation gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| `whoathere-macos-vm` tests | 44 passed, 0 failed |
| Full Rust workspace | 715 passed, 0 failed |
| Swift helper core tests | 53 passed, 0 failed |
| Swift release build | passed |
| Rust formatting | passed |
| Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |

The tests use generated inert bytes and temporary APFS files. They cover first-use authority
consumption, replay rejection, binding mismatch without artifact consumption, wheel provisioning
receipt validation, stopped-base enforcement, APFS clone identity, zero-network configuration,
port separation, cleanup authorization, both supervisor binary targets, and distinct key names.

No restricted sample, registry access, package installation, Python process, pip process, package
import, console entry point, network connection, cloud Mac, or actual VM launch was used.

## Open gates

The next landing must:

1. add a wheel-only stopped-image provisioning and self-test workflow that installs and measures the
   new supervisor, key, config, launch daemon, Python, and pip and writes the exact receipt consumed
   here;
2. produce the wheel backend identity and authority record from the orchestration side without
   operator-authored digests;
3. exercise one inert wheel through an actual local VZ VM and prove VM stop, VSOCK EOF, and clone
   absence from independent host observations;
4. add the fixed offline pip install/import/`.pth`/entry-point runner only after that lifecycle proof;
5. add protected process, file/canary, and network-intent telemetry before making any behavioral
   detection claim; and
6. keep all restricted-malware and cloud-backend gates closed until separately authorized and until
   local detection credibility is established.
