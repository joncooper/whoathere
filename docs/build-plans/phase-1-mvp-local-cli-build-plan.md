# Phase 1 MVP Local CLI Build Plan

## Objective

Build the first usable WhoaThere local CLI on Linux and macOS, with Linux protected containment and macOS beta containment labeling. The goal is not full sandbox maturity; it is a deterministic, testable foundation that intercepts supported workflows, evaluates local policy, emits audit events, and fails closed for high-risk ambiguity.

## Non-Goals

- Production Vault.
- Windows endpoint.
- GA macOS containment.
- Runtime application protection.
- Package-manager forks, TLS MITM, preload enforcement, or WASM primary enforcement.

## Required Source Artifacts

- `outputs/GOAL-07/phase-1-mvp-local-cli-goal.md`
- `outputs/GOAL-09/interface-schema-contracts.md`
- `outputs/GOAL-09/endpoint-egress-decision-table.md`
- `outputs/GOAL-09/macos-beta-containment-positioning.md`
- `outputs/GOAL-09/outage-break-glass-hardening.md`
- `outputs/GOAL-09/primary-owner-test-matrix.md`
- `outputs/GOAL-10/downstream-goal-execution-addendum.md`

## Milestones

| Milestone | Work | Exit evidence |
| --- | --- | --- |
| P1-M1 Workspace foundation | Rust workspace, crates, no-network dependency policy for first scaffold. | `cargo test --manifest-path whoathere/Cargo.toml` passes. |
| P1-M2 CLI skeleton | `whoathere doctor`, `status`, `protect`, `policy explain`, `shim install --dry-run`. | CLI tests cover command dispatch. |
| P1-M3 Config and policy types | Schema-versioned config model, config precedence, mode enum, outage enum, policy decision primitives, exit-code constants. | Unit tests for defaults and fail-closed decisions. |
| P1-M4 Audit/event model | Endpoint event types, redaction result, containment strength, bypass signal. | Unit tests serialize/debug stable event structures or validate fields. |
| P1-M5 Shim scaffold | Real-binary discovery plan and shim manifest generation; dry-run only initially. | Tests prove PATH diagnostics do not mutate host. |
| P1-M6 Sandbox interface | Linux and macOS backend traits plus no-op denied backend for unsupported paths. | Tests verify high-risk unavailable backend fails closed. |
| P1-M7 Fixtures | Synthetic npm/Python malicious fixture directories. | Fixture readme and placeholder scripts exist; no uncontrolled network execution. |

## Repo/File Plan

| Path | Purpose |
| --- | --- |
| `whoathere/Cargo.toml` | Isolated Rust workspace. |
| `whoathere/crates/whoathere-cli` | CLI binary and command dispatch. |
| `whoathere/crates/whoathere-core` | Shared config, mode, endpoint event, package context. |
| `whoathere/crates/whoathere-policy` | Local policy decisions and outage semantics. |
| `whoathere/crates/whoathere-audit` | Redacted audit record builders. |
| `whoathere/crates/whoathere-sandbox` | Sandbox backend traits and beta/unsupported backend labels. |
| `whoathere/tests/fixtures` | npm and PyPI fixture scaffolding. |

## Interfaces/Schemas To Create

- `WhoathereConfig`
- `ExecutionMode`
- `OutageBehavior`
- `EndpointEvent`
- `ContainmentBackend`
- `ContainmentStrength`
- `BypassSignal`
- `PolicyDecision`
- `AuditRecord`
- `SandboxBackend`
- `ExitCode`
- `CommandClassification`

## Test Harness And Fixtures

| Test | Owner | Plan |
| --- | --- | --- |
| CT-002 | Phase 1 | Simulate `npm ci` command classification. |
| CT-003 | Phase 1 | Simulate `npx`/`npm exec` as high-risk transient execution. |
| CT-007 | Phase 1 | Simulate `python -m pip` command shape and protected-mode fail-closed. |
| AT-001 | Phase 1 | Fixture directory for npm postinstall exfil; do not execute uncontrolled network. |
| AT-003 | Phase 1 | Fixture directory for PEP 517 backend behavior. |
| PA-001 | Phase 1 | Redaction unit tests for token-like values. |

## Verification Commands

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- doctor
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- status
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- shim install --dry-run
```

## Release Gate Evidence

- Phase 1-owned tests pass.
- CLI reports macOS beta containment explicitly.
- High-risk unsupported backend fails closed.
- Developer outage behavior does not allow unknown artifacts.
- Audit events never persist raw secrets.

## Security, Privacy, Operations Notes

- Preserve package-manager output once wrapper execution is implemented.
- Never treat registry steering as security boundary.
- `warn_approved_stale` applies only to approved digest-bound artifacts.
- macOS must show `macOS beta containment`, `telemetry/interception only`, or `containment unavailable`.

## Research Required

None blocks this initial scaffold.

## Validation Pending

- Linux kernel primitive implementation.
- macOS VM helper implementation.
- Real npm/pip command compatibility.

## First Implementation Tasks

1. Create Rust workspace and crates.
2. Add config/mode/policy/audit/sandbox primitives.
3. Add CLI skeleton and dry-run commands.
4. Add unit tests.
5. Add fixture directories.

## Reviewer Addendum

Phase 1 should stay narrow: local contracts, command classification, shims, policy/audit, Linux containment proof, and macOS beta labels. Full Vault, scanner, detonator, registry proxy, and production package execution remain out of scope. The first scaffold may avoid external crates to preserve no-network progress; a later implementation pass can introduce `clap`, `serde`, and TOML parsing once dependency policy is decided.
