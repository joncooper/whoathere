# Phase 3 Enterprise Vault Build Plan

## Objective

Build the AWS-first Vault proxy with npm/PyPI-compatible serving, quarantine/promoted CAS, policy/audit integration, deterministic fail-closed behavior, and atomic servable-generation promotion.

## Non-Goals

- Cloudflare-only MVP.
- Advanced detector automation beyond minimum evidence profiles.
- Dashboard polish.
- Promoting artifact classes without completed allow-verdict profiles.

## Required Source Artifacts

- `outputs/GOAL-07/phase-3-enterprise-vault-goal.md`
- `outputs/GOAL-09/vault-promotion-rollback-data-model.md`
- `outputs/GOAL-09/minimum-allow-verdict-research-contract.md`
- `outputs/GOAL-09/interface-schema-contracts.md`
- `outputs/GOAL-09/operations-launch-readiness-addendum.md`
- `outputs/GOAL-09/cloudflare-stale-approved-artifact-policy.md`

## Milestones

| Milestone | Work | Exit evidence |
| --- | --- | --- |
| P3-M1 API/schema | OpenAPI/JSON schema for admission, verdict, artifact, evidence, policy context. | Schema tests and generated Rust types. |
| P3-M2 Data model | Admission request, attempt, artifact blob, metadata snapshot, evidence bundle, verdict, servable generation, alias. | Migration plan and transaction tests. |
| P3-M3 Registry facade | npm packument/tarball and PyPI Simple rendering from active generation. | CT-001/CT-006 compatibility tests. |
| P3-M4 Admission workflow | Fetch to quarantine, integrity verify, job dispatch, verdict gate, generation commit. | OT-002/OT-003 no-promotion tests. |
| P3-M5 AWS IaC | VPC planes, PrivateLink/NLB, S3, DB, queues, worker fleets, NAT/Network Firewall. | IaC plan and threat review. |
| P3-M6 Performance | Warm-cache 1,000 CI benchmark and p99 targets. | PT-001 through PT-004 reports. |
| P3-M7 Minimum control plane | Policy CRUD, break-glass, manual review, audit, privacy export/delete APIs. | Launch-readiness review. |

## Repo/File Plan

- `whoathere/crates/whoathere-vault-api`
- `whoathere/crates/whoathere-registry`
- `whoathere/crates/whoathere-admission`
- `whoathere/crates/whoathere-storage`
- `whoathere/infra/aws/`
- `whoathere/tests/vault/`

## AWS V1 Component Choices

Lock Phase 3 v1 planning to:

- ECS/Fargate for `vault-data-plane`, control API, fetch workers, and admission orchestrator.
- Aurora PostgreSQL for transactional alias/generation commits.
- S3 buckets or prefixes for quarantine, promoted artifacts, evidence, and metadata snapshots.
- SQS plus Step Functions/EventBridge for admission workflows.
- AWS Batch only for heavy detonation jobs that exceed Fargate ergonomics.
- KMS, Secrets Manager, CloudWatch/Otel, NLB/PrivateLink, NAT Gateway, and AWS Network Firewall.

## Required Data Model

Implement at least:

- `tenant`
- `source_registry`
- `admission_request`
- `admission_attempt`
- `artifact_blob`
- `metadata_snapshot`
- `evidence_profile`
- `evidence_bundle`
- `verdict`
- `servable_generation`
- `alias`
- `manual_review`
- `break_glass`
- `audit_event_outbox`

Promotion is one DB transaction that creates a generation and advances the alias pointer only after CAS, metadata, verdict, evidence, tenant/source, and policy checks pass.

## API Schema Requirements

OpenAPI v1 must cover admission, verdict lookup, artifact serving, health/readiness, policy CRUD/validation, namespace/source rules, manual review, break-glass lifecycle, audit search/export, and privacy export/delete. Every non-200 response includes `reason_code`, `retryable`, `audit_event_id`, `policy_version`, and `admission_request_id`.

## Verification Commands

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-vault-api
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-registry
terraform -chdir=whoathere/infra/aws validate
```

## Release Gate Evidence

- No client-observable allow without active servable generation.
- Unknown, scanner-failed, detonator-failed, integrity-failed, or partial-evidence states never serve 200.
- CI has no public fallback.
- Rollback serves last known approved generation or fails closed.

## Research Required

- Artifact-class minimum allow-verdict evidence profiles.
- Minimum admin/control-plane API/UX.
- p99/error-budget targets and scanner/detonator timeout rules.

## Validation Pending

- AWS cost and performance envelope.
- Cloudflare signed stale-approved edge policy if hybrid is enabled later.

## First Implementation Tasks

1. Define API schemas.
2. Define data model and transaction protocol.
3. Implement local in-memory admission prototype.
4. Add no-promotion tests for failure states.
