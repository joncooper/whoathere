# Phase 4 Advanced Detonation Build Plan

## Objective

Build detector, detonator, evidence, anomaly, and manual-review automation needed to decide whether artifact classes can receive allow verdicts.

## Non-Goals

- Full runtime app protection.
- Non-npm/pip ecosystems.
- Claiming dynamic analysis proves benign behavior outside scoped detonation.

## Required Source Artifacts

- `outputs/GOAL-07/phase-4-advanced-detonation-goal.md`
- `outputs/GOAL-09/minimum-allow-verdict-research-contract.md`
- `outputs/GOAL-09/interface-schema-contracts.md`
- `outputs/GOAL-09/outage-break-glass-hardening.md`
- `outputs/GOAL-06/detonation-matrix.md`

## Milestones

| Milestone | Work | Exit evidence |
| --- | --- | --- |
| P4-M1 Evidence profiles | Mandatory evidence by npm/PyPI artifact/source/platform class. | `minimum-allow-verdict-profile.md`. |
| P4-M2 Job schema | Scanner/detonator job schema, result states, timeouts, retry policy. | Schema tests. |
| P4-M3 Static scanners | Manifest/lifecycle/build backend/native/URL/obfuscation signals. | Fixture tests. |
| P4-M4 Dynamic detonators | Linux workers plus selective macOS VM jobs with controlled egress. | AT-001 through AT-008 coverage. |
| P4-M5 Import-time checks | Python import and npm require/import smoke strategy. | AT-004 tests. |
| P4-M6 Manual review | Evidence summary, digest/context-bound decisions, expiry. | Manual-review workflow tests. |
| P4-M7 Incident automation | Customer notification, rule publication, false-positive rollback. | Drill reports. |

## Repo/File Plan

- `whoathere/crates/whoathere-detector`
- `whoathere/crates/whoathere-detonator`
- `whoathere/crates/whoathere-evidence`
- `whoathere/crates/whoathere-review`
- `whoathere/tests/fixtures/`

## Minimum Evidence Profiles To Define First

| Profile | Default posture | Mandatory evidence themes |
| --- | --- | --- |
| `npm.registry_tarball.v1` | eligible for auto-allow after all mandatory jobs pass | manifest/lifecycle static scan, SRI/hash verification, release diff, Linux CI lifecycle detonation, import/require smoke, no-network plus recorded-egress modes. |
| `npm.native_extension.v1` | eligible only after native build/import coverage | registry tarball evidence plus native build/import on Linux and selective macOS when required. |
| `npm.untrusted_source.v1` | manual_review or deny by default | pinned digest/ref/source policy, static scan, no CI auto-allow unless policy and evidence are complete. |
| `pypi.wheel.v1` | eligible for auto-allow after all mandatory jobs pass | metadata/hash/yanked/tag validation, wheel tag platform coverage, install/import smoke, native marker handling. |
| `pypi.sdist_pep517.v1` | eligible only after isolated build evidence | PEP 517 build in isolation, build dependencies through Vault, generated wheel install/import smoke. |
| `pypi.editable_vcs_direct.v1` | manual_review or deny by default | pinned source/digest/ref, source policy, evidence completeness; no default CI auto-allow. |

Each profile must declare mandatory jobs, optional jobs, platform target set, never-auto-allow source types, timeout behavior, and whether human review can approve after evidence is complete.

## Job Schema Additions

Add fields to the GOAL-09 job contract:

- `profile_id`
- `profile_version`
- `job_kind`
- `job_action_set`
- `worker_image_digest`
- `toolchain_versions`
- `sandbox_backend`
- `environment_profile`
- `network_mode`
- `expected_evidence_refs`
- `reason_codes`
- `resource_usage`
- `idempotency_key`

## Verification Commands

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-detector
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-evidence
```

## Release Gate Evidence

- AT-004, AT-005, AT-008, AT-009 primary tests pass.
- Evidence profiles exist for every artifact class Phase 3 can promote.
- Scanner/detonator outage cannot produce allow.
- Manual review binds to digest, source, metadata context, policy version, evidence bundle, approver, and expiry.
- Missing mandatory evidence returns `pending`, `manual_review`, `deny`, or `503`, never `allow`.

## Research Required

- Exact evidence sufficiency thresholds.
- Sandbox fingerprinting and evasive payload strategy.

## Validation Pending

- macOS detonation capacity and cost.
- False positive/negative review workflow.

## First Implementation Tasks

1. Write evidence-profile table.
2. Define job schema and result enum.
3. Add static manifest scanner prototype.
4. Add fixture harness.

## Manual Review Rule

Manual review is an adjudication layer, not an override path. If integrity, source policy, redaction, or profile-mandatory jobs are incomplete, the only valid reviewer action is `needs_more_evidence`.
