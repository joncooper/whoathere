# Artifact-Native Linux VZ Unqualified Backend Checkpoint

Date: 2026-07-11

Status: Rust and Swift share an exact measured Linux VZ backend identity that is structurally unable
to authorize execution; no Linux image, VM, sensor, or conformance receipt exists yet

Canonical references:

- [Artifact-Native Telemetry Feasibility Decision](artifact-native-telemetry-feasibility-decision-2026-07-11.md)
- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Build-Execution Grant Checkpoint](artifact-native-sdist-build-execution-grant-checkpoint-2026-07-11.md)

## Outcome

`whoathere.macos_linux_vz_telemetry_backend_identity.v1` binds the candidate backend’s:

- base generation, Linux distribution, and kernel release identifiers;
- kernel image, initramfs, root disk, kernel configuration, and BTF digests;
- root-owned guest runner, sensor, BPF bundle, and sensor-configuration digests;
- guest and host evidence public-key digests;
- macOS host helper, packet sensor, and packet-sensor configuration digests;
- protected-telemetry requirements digest; and
- dedicated package UID and GID.

The only representable qualification state is `candidate_unqualified`. The Rust type returns
`executionAuthorityPermitted=false`, and requesting authority returns
`macos_linux_vz_telemetry_conformance_missing`. There is no `qualified`, `ready`, `clean`,
`execution_enabled`, or sync-back field.

The Rust constructor computes the requirements digest from the closed
`whoathere.artifact_protected_telemetry_requirements.v1` value. The decoder requires an independently
supplied expected requirements object and rejects rebinding. Every measured component contributes to
the canonical identity digest.

The Swift VZ helper independently checks the exact key set, schema, unqualified state, identifier
grammar, canonical UID/GID values, every digest, canonical JSON encoding, and expected requirements
digest. Rust and Swift fixtures agree on both the requirements digest and full identity digest.

## Verification

Tests prove:

- every measured input is bound into the identity digest;
- requirement substitution is rejected;
- an attempted `qualified` state is rejected as an unknown enum value;
- unknown execution fields and noncanonical wire encodings are rejected;
- the Swift parser matches the Rust canonical golden; and
- neither language can derive execution authority from this identity.

Verification commands completed successfully:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
swift test
```

The Rust suite includes two Linux VZ identity tests and 25 sdist backend tests. The Swift helper
suite passed 88 tests. No VM, kernel, initramfs, package manager, package code, public network,
restricted sample, or malware was used.

## Next gate

The follow-on [telemetry-conformance run-spec checkpoint](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md)
now defines a closed request that nests this unqualified identity and the full telemetry
requirements while keeping package execution absent. The next backend slice must build an inert
measured image and sensor conformance workflow that produces separately authenticated guest and
host receipts.

A future qualified backend must be a distinct type constructible only from those verified receipts;
it must not add a mutable qualification flag to this identity. Only that distinct type may become
an input to execution-authority issuance.
