# GOAL-07: Engineering Roadmap Goal Pack

## Objective

Generate the downstream implementation-roadmap goals that, when executed, produce granular build plans for a working WhoaThere system.

## Required Inputs

This goal must consume the outputs from GOAL-01 through GOAL-06 and GOAL-08. It must not invent architecture or policy decisions that conflict with those outputs.

## Required Downstream Phase Goals

### Phase 1: MVP Local CLI

Produce a build plan for:

- Rust CLI and local engine.
- PATH shims for npm and pip workflows.
- Local policy file and explainable decisions.
- Linux sandbox MVP and macOS beta containment spike.
- Basic audit log.
- Fixture tests for malicious npm and Python install/build payloads.

Exit condition: a developer can run protected npm and pip installs on Linux and see deterministic allow/block/warn outcomes; macOS produces deterministic outcomes with explicit beta containment or telemetry-only labeling.

### Phase 2: Advanced Cross-Platform Isolation

Produce a build plan for:

- Hardened Linux namespace/seccomp/cgroup/Landlock backend.
- macOS VM-backed GA containment validation or chosen alternative.
- Compatibility matrix for real packages such as native modules and Python sdists.
- Backstop telemetry for missed invocations.
- CI/container mode.

Exit condition: endpoint protection has measured compatibility and containment guarantees for supported workflows.

### Phase 3: Enterprise Vault Proxy

Produce a build plan for:

- npm/PyPI-compatible Vault proxy.
- Quarantine CAS and promoted serving namespace.
- Policy service, audit events, auth, and minimum safe admin/control-plane API workflows.
- AWS and/or Cloudflare deployment based on completed ADRs.
- CI fail-closed routing through Vault.

Exit condition: developers and CI can consume approved packages through Vault with scan-before-serve semantics, and cold-miss promotion is enabled only for artifact classes with complete minimum allow-verdict profiles.

### Phase 4: Advanced Detonation And Automation

Produce a build plan for:

- Full detonation matrix.
- Import-time behavior analysis.
- Maintainer/release anomaly detection.
- Manual review and automation workflows.
- Performance and reliability hardening.
- Multi-tenant operational readiness.

Exit condition: Vault can automatically quarantine suspicious package releases and provide evidence for security review.

## Required Deliverables

- `phase-1-mvp-local-cli-goal.md`
- `phase-2-advanced-isolation-goal.md`
- `phase-3-enterprise-vault-goal.md`
- `phase-4-advanced-detonation-goal.md`
- `roadmap-dependency-graph.md`
- `release-gates.md`
- `not-now-list.md`

## Acceptance Criteria

- Each phase goal has objective, scope, non-goals, deliverables, acceptance tests, dependencies, and exit gate.
- Phase goals compose into a working deployable system without hidden prerequisite work.
- Windows is placed explicitly after the first macOS/Linux endpoint track.
- The roadmap preserves fail-closed CI semantics and scan-before-serve Vault semantics.
- The roadmap includes performance, operations, privacy, and security gates, not only feature work.

## Exit Gate

The final roadmap is accepted only if another engineer or agent can pick up Phase 1 and produce a granular implementation plan without asking what the product is supposed to protect.

## Suggested Subagents

- Program planning reviewer.
- Security roadmap reviewer.
- Developer-experience reviewer.
- Operations/reliability reviewer.
