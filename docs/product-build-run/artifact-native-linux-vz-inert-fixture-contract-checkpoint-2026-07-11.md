# Artifact-Native Linux VZ Inert-Fixture Contract Checkpoint

Date: 2026-07-11

Status: one closed, non-executing action contract covers all 38 canonical telemetry-conformance
cases; no fixture behavior, sensor, VM run, receipt, backend qualification, or package execution
exists from this slice

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Linux VZ Conformance Run-Spec Checkpoint](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md)
- [Linux VZ Inert-Image Candidate Checkpoint](artifact-native-linux-vz-inert-image-candidate-checkpoint-2026-07-11.md)

## Outcome

`fixture_cases.def` is a single ordered X-macro table for the exact 38-case Rust conformance
matrix. Every row fixes:

- canonical case name;
- fixture family;
- expected terminal semantics;
- trigger owner;
- one closed inert action name; and
- one closed network policy.

Rust independently parses the table and compares every row, in order, with
`ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1`, `fixture_for_case_v1`, and
`expected_terminal_for_case_v1`. It also checks the exact trigger-owner and network-policy mapping,
case uniqueness, action uniqueness, and restricted action alphabet.

The three network policies are:

- `none`;
- `guest_sinkhole_only`, for intent that must terminate at the no-route raw-frame sinkhole; and
- `host_sinkhole_overflow`, only for the explicit host drop-accounting fault injection.

No row can select ambient networking, a resolver, a registry, a live address, an arbitrary target,
or a package operation.

## Non-executing inspector

The portable inspector compiles the same table into a fixed descriptor binary. It accepts only:

```text
--list
--describe CASE
```

Descriptions are closed canonical JSON and repeat:

- `operation=describe_only`;
- `external_route=false`;
- `package_execution=false`; and
- `sync_back=false`.

Unknown cases, `--execute`, extra arguments, and every unrecognized option fail closed. Source tests
also reject command, path, environment, process-execution, and socket input surfaces. The inspector
does not implement any named action.

## Measurements and verification

Two independent cross-compiles produced the same stripped static aarch64 Linux binary:

| Object | SHA-256 |
| --- | --- |
| Ordered fixture table | `cab0cceb7c6ff6c734a8d6ab4040aeeef97265b59f5e71be507e51f6c63b8dc9` |
| Inspector source | `df738187ec1890d289d9eb428f8466a13b15e2c7987c69bf32476b8b61fc3d62` |
| Static aarch64 descriptor | `c36ca3da6dac87497f50c3718162acdbe2b98fa65576f81c953d58ffd6f47f4c` |

The following completed successfully:

```sh
whoathere/helpers/linux-vz-conformance/scripts/verify-fixture-contract.sh
cargo test --manifest-path whoathere/Cargo.toml \
  -p whoathere-macos-vm \
  --test linux_vz_fixture_contract_v1
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml \
  -p whoathere-macos-vm --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
```

The shell verifier compiles with warnings denied, runs all 38 native descriptions, checks exact JSON
keys and fixed safety values, rejects unknown/execution-shaped inputs, performs two deterministic
aarch64 builds, and checks the resulting ELF architecture, static linkage, and stripping. The Rust
integration test passed both semantic and input-surface tests. The full Rust macOS VM package passed
90 tests, Clippy passed with warnings denied, and formatting passed.

## Claim boundary and next gate

This checkpoint closes vocabulary and ownership drift before behavior implementation. The aarch64
descriptor is deliberately not called or bound as the guest runner. It cannot run a fixture,
observe an event, sign evidence, qualify a backend, or issue execution authority.

The next evidence-bearing step remains the exact inert-image boot on an independently identified
physical Apple Silicon Mac. After that boot proves the kernel/initramfs path, implement the closed
actions behind authenticated, one-case-only guest control; measure the actual runner, sensors, BPF
objects, configuration, and keys; then run the complete 38-case matrix on unique disposable clones.

The configured remote Mac remains gated by independent confirmation of its changed SSH host key.
Strict host-key checking was not weakened. No package artifact, package manager, package code,
restricted sample, malware, live C2, second stage, sync-back path, or public guest route was used.
