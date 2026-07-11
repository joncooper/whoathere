# Artifact-Native Linux VZ Complete-Matrix Qualification Checkpoint

Date: 2026-07-11

Status: the complete 38-case aggregate can construct a distinct qualified Rust backend type from
verified inert receipts; only synthetic test receipts exist, so no real backend is qualified

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Telemetry Feasibility Decision](artifact-native-telemetry-feasibility-decision-2026-07-11.md)
- [Authenticated Conformance-Evidence Checkpoint](artifact-native-linux-vz-authenticated-conformance-evidence-checkpoint-2026-07-11.md)
- [Linux VZ Conformance Run-Spec Checkpoint](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md)

## Outcome

`QualifiedMacosLinuxVzTelemetryBackendV1` has private fields and no public decoder or general
constructor. The only construction path consumes verified single-case observations and requires:

- exactly 38 observations;
- every closed conformance case exactly once;
- one backend identity and one telemetry-requirements digest throughout;
- unique challenge, run-spec, and disposable-clone bindings for every case;
- already verified guest/host signature and case-terminal semantics; and
- no execution authority on any input.

Omissions, duplicate cases, mixed backend or requirements identities, challenge/run/clone reuse,
preexisting execution authority, invalid backend state, and serialization or size failures are
distinct fail-closed errors.

The aggregate sorts case bindings canonically, so input order cannot change the qualification
identity. It binds the complete evidence-set digest, full unqualified backend identity, exact
requirements digest, and all case/challenge/run/clone bindings into
`whoathere.macos_linux_vz_qualified_telemetry_backend.v1`.

## Authority boundary

The qualified type is not an execution grant. Its fixed record says:

- qualification state is `complete_inert_conformance_matrix_verified`;
- execution eligibility is `typed_package_scenario_authority_request_only`;
- `execution_authority_issued=false`;
- clone policy is one unique destroyed clone per case; and
- sync-back is `structurally_absent`.

The Rust API reports that the backend is eligible to request a future typed package-scenario
authority, while `package_execution_authority_permitted=false` and `sync_back_permitted=false`.
Actual authority issuance remains a separate unimplemented boundary.

Swift independently validates the canonical qualification record, exact sorted case matrix,
backend and evidence-set digests, unique challenge/run/clone identities, fixed policies, and
guest-receipt-presence rules. Its parsed-record type deliberately reports execution-authority
request, package-execution, and sync-back permission as false: parsing a record is not re-verifying
the underlying receipts and cannot mint authority.

## Verification

Synthetic fixtures exercise all 38 cases through the real run-spec, challenge, guest/host signing,
signature verification, case-semantics verification, and aggregate construction paths. They cover
ordinary completion, timeout teardown, intentional guest and host drop detection, guest/host sensor
death, channel interruption, VM stop, access denial, and every network/process/file/platform case.

Adversarial tests reject matrix omission, case duplication, clone reuse, backend mixing, and an
otherwise valid host-signed receipt that reports an externally forwarded frame. Reversing all 38
inputs produces the same canonical qualification record.

The Rust and Swift canonical golden is:

`sha256:455c3566f07451d9a763ba594652938aced20bd8f90eb7c712995a8e13e91c1a`

The following completed successfully:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
swift test
```

The Rust macOS VM package passed 88 tests, including two complete-matrix qualification tests. The
Swift helper passed 94 tests, including independent qualification-record validation. No VM, real
sensor, package manager, package code, public network target, restricted sample, or malware was
used.

## What remains unproven

This implementation proves type and protocol behavior with synthetic signed evidence. It does not
prove that a Linux image boots, required kernel facilities exist, sensors observe the claimed
events, raw frames are sinkholed, faults become visible, descendants are killed, clones are
destroyed, or package-UID isolation works on a real VM.

Consequently, the repository contains a qualification mechanism but no actual qualified backend.
No production execution issuer consumes the qualified type.

## Next gate

Build the pinned Linux kernel, initramfs, root disk, root-owned runner/sensors/BPF bundle, guest and
host evidence keys, and host raw-frame sinkhole. Measure them into the unqualified identity and run
the 38 inert cases on unique disposable VZ clones. Persist only sanitized receipt and qualification
digests in tracked paths.

Only after those real receipts construct the qualified type should the project implement a
single-use typed execution-authority issuer and true Linux-target npm, wheel, and sdist scenarios.
