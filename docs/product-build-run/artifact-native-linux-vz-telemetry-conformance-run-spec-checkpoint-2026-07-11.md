# Artifact-Native Linux VZ Telemetry-Conformance Run-Spec Checkpoint

Date: 2026-07-11

Status: Rust and Swift share a closed run-spec contract for trusted inert telemetry fixtures; no
Linux image, VM, sensor, fixture binary, conformance evidence, qualification receipt, or package
execution exists yet

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Telemetry Feasibility Decision](artifact-native-telemetry-feasibility-decision-2026-07-11.md)
- [Artifact-Native Linux VZ Unqualified Backend Checkpoint](artifact-native-linux-vz-unqualified-backend-checkpoint-2026-07-11.md)

## Outcome

`whoathere.macos_linux_vz_telemetry_conformance_run_spec.v1` is a canonical, digest-bound request
for exercising one trusted inert telemetry fixture against one exact unqualified Linux VZ backend.
It nests and binds the full protected-telemetry requirements object and the full measured backend
identity rather than accepting mutable readiness flags or ambient host configuration.

The closed fixture set is:

| Fixture | Required observations |
| --- | --- |
| `process_lineage` | fork/exec/exit, credentials, dynamic libraries, heartbeat, drops |
| `file_canary` | open/read/write, mmap, persistence writes, filesystem diff, heartbeat, drops |
| `network_intent` | guest intent, host raw frames, DNS/HTTP sinkholes, listener diff, heartbeat, drops |
| `drop_accounting` | sensor heartbeat and dropped-event accounting |
| `teardown_stress` | lineage, listener diff, descendant teardown, heartbeat, drops, clone lifecycle |
| `sensor_tamper` | credentials, protected file access, heartbeat, drops, clone lifecycle |

Every run spec fixes all of the following:

- execution posture is `trusted_inert_fixture_only_no_package_code`;
- package execution is `disabled`;
- network topology is a host raw-frame sinkhole with `no_external_route`;
- clone policy is one boot, one fixture, then destroy;
- sync-back is `structurally_absent`;
- wall-clock, guest-event, host-frame, and evidence-byte limits are fixed; and
- the guest protocol is independently domain-separated from npm, wheel, and sdist protocols.

There is no artifact coordinate, artifact digest, package-manager command, arbitrary command,
environment injection, execution-authority token, clean/allow result, qualification state, or
sync-back enablement in the schema. The Rust and Swift result types both report that package
execution authority is not permitted.

This contract is intentionally a conformance request, not a conformance result. It does not prove
that a fixture ran, a sensor observed anything, an image is qualified, or a package may execute.

## Cross-language binding

Rust compiles the wire object and validates it again through the same strict decoder. Swift
independently checks the exact key set, canonical JSON, fixed policies and limits, fixture-to-sensor
mapping, nested requirements, nested unqualified backend, and both nested digests.

The shared `network_intent` golden binds:

- protected-telemetry requirements:
  `sha256:3ff8c862243232fbc48ec91d5926e587bf9817f678853d02d9730cde2c464946`;
- unqualified backend identity:
  `sha256:45c12920320ff882bf39fa45a9a746d51d635973843d05817939df0afdf3fdc6`;
- conformance run spec:
  `sha256:325a67c4e1690f2b04b6735d5f4463beb248ce68e15868e0337d4b0443ddd671`.

Tests reject missing or reordered fixture sensors, backend digest rebinding, requirements sensor
gaps, enabled package execution, unknown execution fields, cross-schema replay, trailing bytes, and
noncanonical JSON.

## Verification

The following completed successfully:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
swift test
```

The Rust macOS VM package passed 82 tests, including three conformance run-spec tests. The Swift
helper passed 90 tests, including two independent conformance parser tests. No VM, package manager,
package code, public network target, restricted sample, or malware was used.

## Next gate

Build and measure a minimal Linux VZ image containing only the root-owned runner, protected sensors,
BPF objects, configuration, evidence key, and trusted inert fixtures. Implement separately
authenticated guest and host conformance evidence, then run the six fixtures with fault injection
for drop, sensor-death, channel-loss, timeout, and teardown paths.

A distinct qualified-backend type may be constructed only from verified conformance receipts that
prove every requirement for the exact backend identity. The current unqualified identity and this
run spec must remain unable to issue package-execution authority. True Linux-target npm, wheel, and
sdist scenario compilation follows qualification; existing macOS/arm64 package templates must not
be relabeled as Linux templates.
