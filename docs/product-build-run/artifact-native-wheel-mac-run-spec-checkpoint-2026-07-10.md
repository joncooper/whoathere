# Artifact-Native Wheel Mac Run-Spec Checkpoint

Date: 2026-07-10

Status: validated wheel templates compile into a distinct measured Mac run-spec contract; binary
submission, Swift decoding, guest execution, pip, and Python probes are not implemented by this
checkpoint

Canonical references:

- [Artifact-Native Wheel Scenario Compiler Checkpoint](artifact-native-wheel-scenario-compiler-checkpoint-2026-07-10.md)
- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native npm Mac Run-Spec and Transport Checkpoint](artifact-native-npm-mac-run-spec-transport-checkpoint-2026-07-10.md)

## Outcome

The Mac backend no longer has to misrepresent a wheel as an npm scenario to bind it to a measured
VM base. `whoathere-macos-vm` now defines a separate `whoathere.macos_wheel_run_spec.v1` schema and
`whoathere.wheel_artifact_scenario.v1` guest-protocol identity.

The compiler accepts only a canonical, digest-valid `whoathere.wheel_scenario_template.v1`. It
reparses that template through the strict wheel decoder, verifies its recorded template digest, and
requires exact agreement with the backend's measured:

- Python version and executable digest;
- pip version and CLI digest;
- stopped-base generation and disk identity;
- auxiliary storage, hardware model, and machine identifier;
- post-provisioning receipt;
- signed helper and root guest-supervisor digests;
- guest authentication public key;
- root-owned runner configuration;
- fixed `_whoatherepkg` name and dedicated package UID/GID;
- CPU and memory allocation;
- APFS clone implementation; and
- wheel-specific guest-protocol digest.

The resulting run spec nests the complete canonical wheel template and fixes the VM posture to an
APFS clone with no byte-copy fallback, zero configured network devices, and one boot/one
scenario/clone destruction. Changing a wheel byte, template, Python/pip measurement, base disk, or
other backend identity changes the run-spec digest or fails compilation.

## Ecosystem separation

The existing npm Mac schema and its Node/npm backend identity are unchanged. The wheel run spec has
Python/pip measurements and contains no Node/npm fields. The npm decoder rejects the wheel schema,
and the wheel decoder rejects npm schema/protocol substitution.

This separation is intentional. It avoids claiming the current npm Swift parser, binary submission
frame, or guest supervisor understands wheel semantics. A later bridge must explicitly add the
wheel schema to those layers and retain the same cross-ecosystem rejection behavior.

## Closed no-sync contract

The wheel run spec has no sync-back field, host output path, registry, free-form argv, shell string,
or verdict. Unknown fields, including `sync_back`, fail strict decoding. The nested scenario still
requires a fresh virtual environment, `no_index_no_dependencies`, a fresh interpreter per probe,
zero NICs, the unprivileged package identity, and clone destruction.

## Verification

| Gate | Result |
| --- | --- |
| Wheel Mac run-spec integration tests | 3 passed, 0 failed |
| `whoathere-macos-vm` tests | 31 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 702 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |
| Existing Swift helper core tests | 31 passed, 0 failed |

The focused tests prove strict round-trip decoding, exact template and scenario-kind retention,
npm/wheel decoder separation, Python/pip capability mismatch rejection, noncanonical and unknown
field rejection, schema and guest-protocol substitution rejection, invalid package identity
rejection, and run-spec rebinding for exact wheel and base-disk changes.

All fixtures were inert wheel ZIP bytes generated in memory with a complete hash-checked `RECORD`.
No restricted sample, network, registry, cloud Mac, VM, guest process, pip process, Python import,
or package code was used.

## Open gates

This checkpoint is a run-spec bridge, not an executable backend. The next required work is:

1. add a wheel-specific authenticated binary submission frame or a reviewed ecosystem-tagged V2
   frame without weakening the npm frame;
2. implement strict Swift decoding for the wheel run spec and reject cross-ecosystem substitution;
3. extend stopped-base provisioning receipts with measured Python/pip and wheel-runner identities;
4. authenticate the wheel guest session and stage the exact wheel without execution;
5. complete the reviewed package-account privilege drop;
6. implement the fixed offline wheel runner and protected telemetry; and
7. prove the `.pth`, import-root, and console-entry matrix in disposable zero-NIC clones before any
   detection or clean-result claim.

The cloud-Mac host-key trust gate remains open. SSH host-key verification has not been bypassed.
