# Phase 4 Goal: Advanced Detonation And Automation

## Objective

Build advanced scanning, detonation, anomaly detection, manual review automation, and multi-tenant operational readiness on top of the Phase 3 Vault.

## Source ADRs And Inputs

- ADR-009 detonation runtime.
- GOAL-06 admission pipeline, signal inventory, detonation matrix, evidence model.
- GOAL-05 manual review and audit model.
- GOAL-08 incident response and telemetry boundaries.
- GOAL-09 minimum allow-verdict research contract, primary-owner test matrix, outage/break-glass hardening, and operations launch-readiness addendum.

## Locked Product Decisions

- Artifacts enter quarantine before analysis.
- Only allow verdict promotes, and only after the artifact-class minimum evidence profile passes.
- Linux detonation workers are primary; macOS VM workers are selective.
- Evidence is structured and redacted.
- Manual review decisions bind to digest and metadata context.

## Scope

- Full detonation matrix.
- Artifact-class minimum allow-verdict evidence profiles.
- Import-time behavior analysis.
- Maintainer/release anomaly detection.
- DNS/HTTPS exfil detection.
- Native extension behavior capture.
- Manual review workflow.
- Customer notification and incident automation.
- Multi-tenant readiness.

## Non-Goals

- Full runtime app EDR.
- Arbitrary non-npm/pip ecosystems unless separately planned.

## Owned Interfaces

- Scanner/detonator job schema.
- Evidence bundle model.
- Artifact-class evidence profile schema.
- Manual review workflow.
- Advanced audit/evidence references.

## Delegated Interfaces

- Runtime application protection to future product line.

## Acceptance Tests

Primary owns AT-004, AT-005, AT-008, AT-009, OT-002, OT-003, and Phase 4 detection evidence for PA-001/PA-002. Contributes detection evidence for AT-001, AT-002, AT-003, AT-006, and AT-007 under GOAL-09 primary-owner assignments.

## Deliverables

- Detonation worker implementation plan.
- Minimum allow-verdict evidence profile table.
- Evidence storage implementation plan.
- Manual review service plan.
- Anomaly signal implementation plan.
- Incident automation plan.
- Multi-tenant operations readiness checklist.

## Exit Gate

Vault can automatically quarantine suspicious package releases, provide evidence for security review, and produce artifact-class allow-verdict evidence profiles that Phase 3 can enforce.

## Risks Accepted

Dynamic analysis remains probabilistic and cannot prove benign runtime behavior outside scoped detonation.
