# Phase 3 Goal: Enterprise Vault Proxy

## Objective

Build and deploy the enterprise Vault proxy with npm/PyPI compatibility, scan-before-serve admission, AWS MVP deployment, policy integration, auth, audit, and CI fail-closed routing.

## Source ADRs And Inputs

- ADR-005 AWS deployment.
- ADR-006 Cloudflare rejection.
- ADR-007 hybrid extension.
- ADR-011 final deployment recommendation.
- GOAL-04 cache/storage, state machine, fail-closed matrix, performance plan.
- GOAL-05 policy/audit.
- GOAL-08 operations/privacy/SLOs.
- GOAL-09 Vault promotion/rollback model, minimum allow-verdict research contract, Cloudflare stale-approved policy, operations launch-readiness addendum, phase-gate scorecard, and primary-owner test matrix.

## Locked Product Decisions

- AWS-only is MVP production architecture.
- AWS is authoritative for core secrets, keys, CAS, metadata, verdicts, policy, audit, evidence, and deployment state.
- Cloudflare hybrid is optional later and non-authoritative for core.
- Scan-before-serve is mandatory.
- CI fails closed on Vault/scanner/policy ambiguity.
- Cold-miss production promotion is allowed only after the artifact class satisfies the GOAL-09 minimum allow-verdict research contract.

## Scope

- npm registry-compatible metadata/tarball serving.
- PyPI Simple API-compatible serving.
- Quarantine/promoted CAS.
- Metadata/verdict DB.
- Admission state machine.
- Policy service integration.
- Audit event pipeline.
- AWS IaC plan.
- CI routing and private network controls.
- Warm-cache performance benchmark.
- Atomic promotion and rollback model using servable generations.
- Minimum control-plane API/UX research for safe enterprise operation.

## Non-Goals

- Cloudflare hybrid production rollout.
- Full advanced detonation automation.
- SaaS dashboard polish.

## Owned Interfaces

- Vault admission API.
- Registry compatibility.
- Cache object naming.
- Provider authority contract.
- Secret/key lifecycle.
- Vault fail-closed HTTP semantics.

## Delegated Interfaces

- Advanced detection models to Phase 4.
- Exact allow-verdict evidence profiles to the Phase 3/4 research loop defined in GOAL-09.
- Dashboard polish to later product work. Minimum control-plane API/UX is in scope for Phase 3 research.

## Acceptance Tests

Primary owns CT-001, CT-005, CT-006, CT-008, CT-009, AT-010, OT-001 through OT-004, OT-006 through OT-008, PT-001 through PT-004, PA-002, PA-003, and scan-before-serve validation for artifact classes whose minimum allow-verdict profile is complete.

## Deliverables

- Vault proxy implementation plan.
- AWS deployment implementation plan.
- CAS/metadata implementation plan.
- Policy/audit integration plan.
- CI integration guide.
- Performance benchmark harness.
- Rollback and DR runbooks.

## Exit Gate

Developers and CI can consume approved packages through Vault with scan-before-serve semantics and deterministic fail-closed behavior.

## Risks Accepted

Cold-miss latency may require prewarm workflows for CI. Phase 3 may promote cold-miss artifacts in production only for artifact classes with complete minimum allow-verdict evidence profiles and passing atomic promotion tests.
