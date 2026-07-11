# Artifact-Native Linux VZ Authenticated Conformance-Evidence Checkpoint

Date: 2026-07-11

Status: domain-separated guest and host conformance receipts are implemented and independently
verified in Rust and Swift; no receipt from a real VM or sensor exists, and no backend is qualified

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Telemetry Feasibility Decision](artifact-native-telemetry-feasibility-decision-2026-07-11.md)
- [Linux VZ Conformance Run-Spec Checkpoint](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md)
- [Linux VZ Unqualified Backend Checkpoint](artifact-native-linux-vz-unqualified-backend-checkpoint-2026-07-11.md)

## Outcome

Two distinct canonical evidence schemas now consume the fresh, clone-bound conformance challenge:

- `whoathere.macos_linux_vz_telemetry_guest_receipt.v1` is signed by the measured guest evidence
  key; and
- `whoathere.macos_linux_vz_telemetry_host_receipt.v1` is signed by the independently pinned host
  evidence key.

The schemas have separate Ed25519 signature domains and exact key sets. A guest receipt cannot be
decoded or verified as a host receipt, and the reverse is also rejected.

Both receipts bind the challenge, run spec, backend, requirements, clone, fixture family, exact
conformance case, measured runner, expected terminal semantics, exact authority-specific sensor
set, and a digest plus byte length for the canonical detailed-evidence payload.

The guest receipt additionally binds:

- event sequence start/end, event count, heartbeat count, and dropped-event count;
- sensor health, truncation state, and descendant teardown;
- the dedicated package UID/GID, absence of capabilities, and absence of public-network reachability;
- package execution `disabled`; and
- sync-back `structurally_absent`.

The host receipt additionally binds:

- host event sequence start/end, event count, heartbeat count, and dropped-frame count;
- packet-sensor health and truncation state;
- guest-channel termination, VM start/stop, and clone destruction;
- zero externally forwarded frames and no public-network route;
- package execution `disabled`; and
- sync-back `structurally_absent`.

Signing seeds are zeroized after Ed25519 key construction. Verification requires independently
supplied public-key bytes whose digests match the keys pinned in the measured backend and challenge.

## Case semantics

Receipt signature verification and case conformance are separate operations. A valid signature can
truthfully report a failed or incomplete run; it does not make that run conforming.

The Rust single-case verifier checks the signed observations against the run spec’s expected
terminal class:

- ordinary, timeout, and access-denial cases require healthy, untruncated, zero-drop guest and host
  evidence plus complete descendant/VM/clone teardown;
- BPF and fanotify fault-injection cases require an explicit guest drop with no host drop;
- host-frame overflow requires an explicit host drop with no guest drop;
- guest-sensor death requires the guest receipt to be absent while the host proves the expected
  infrastructure error and teardown;
- host-sensor death requires a healthy guest receipt and an unhealthy host packet-sensor claim; and
- channel interruption and VM stop may omit the guest receipt but still require host-authenticated
  lifecycle teardown.

All cases require zero externally forwarded frames. The verified receipt and verified-case types
remain structurally unable to authorize package execution.

This is not yet the complete 38-case qualification aggregate. No receipt or one valid case can
construct a qualified backend.

## Cross-language verification

Rust signs deterministic fixtures with distinct guest and host seeds. Swift independently rebuilds
the exact unsigned canonical claims, verifies the Rust Ed25519 signatures with CryptoKit, and
rejects key, schema, authority, claim, sensor, execution, egress, signature, and canonicalization
mutations.

Shared fixture digests are:

- guest unsigned claims:
  `sha256:a6a9a44200b03f9865b8ad1a7d5eb58c6bcadd39499f13a22856926e65acec92`;
- host unsigned claims:
  `sha256:e983821449e2c24ecd5fb70e7f214fce38f8471314ac0e61f4b5647cc3c3d979`;
- signed guest receipt:
  `sha256:9bad56c2d3def2391e9f164f7262963c83ec7ba2fe3946e7301bc3d7122224ef`; and
- signed host receipt:
  `sha256:48a21bb1719681148070688cbf3bf890ca7c84c735eb5ba954558179608dac43`.

## Verification

The following completed successfully:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
swift test
```

The Rust macOS VM package passed 86 tests, including four Linux VZ evidence tests. The Swift helper
passed 93 tests, including independent verification of both Rust-signed receipts. No VM, sensor,
package manager, package code, public network target, restricted sample, or malware was used.

## Next gate

Implement the complete-matrix qualification aggregate. It must require exactly one verified result
for every closed conformance case, reject duplicates, omissions, backend or requirements mixing,
clone reuse, unexpected terminals, unhealthy/truncated evidence, unexplained drops, incomplete
teardown, and any external frame forwarding. Only that aggregate may construct a distinct qualified
backend type.

After the aggregate is complete, build and measure the Linux image, guest sensors, host packet
sensor, evidence keys, and trusted runner; then execute the inert conformance matrix. Until measured
receipts pass, the candidate backend remains unqualified and package execution remains disabled.
