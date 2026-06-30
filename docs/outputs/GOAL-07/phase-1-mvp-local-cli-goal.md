# Phase 1 Goal: MVP Local CLI

## Objective

Build a local WhoaThere CLI MVP for macOS and Linux that intercepts npm and pip workflows, evaluates policy, emits audit events, proves Linux malicious install/build fixture containment for the first vertical slice, and delivers macOS beta containment with explicit limitations.

## Source ADRs And Inputs

- GOAL-01 product scope and policy posture.
- ADR-001 Rust language selection.
- ADR-002 interception strategy.
- ADR-003 Linux isolation.
- ADR-004 macOS isolation.
- ADR-008 policy distribution.
- ADR-010 telemetry boundaries.
- GOAL-09 macOS beta containment positioning, endpoint egress decision table, interface schema contracts, phase-gate scorecard, and primary-owner test matrix.

## Locked Product Decisions

- Rust CLI/local engine.
- PATH shims plus config steering.
- Linux rootless sandbox MVP.
- macOS VM-backed beta containment path with telemetry fallback and no GA containment claim.
- CI/high-risk fail closed.
- No TLS MITM, package-manager fork, `LD_PRELOAD`, `DYLD_*`, or WASM primary enforcement.

## Scope

- `whoathere` CLI command skeleton.
- Shims for `npm`, `npx`, `pip`, `pip3`.
- Protected handling for `python -m pip`.
- Local signed policy snapshot.
- Basic audit log.
- Linux sandbox MVP.
- macOS beta containment spike and UX labeling.
- Synthetic malicious npm/Python fixtures.

## Non-Goals

- Production Vault.
- Multi-tenant admin UI.
- Windows endpoint.
- Full runtime app protection.

## Owned Interfaces

- CLI commands and exit codes.
- Local config MVP.
- Endpoint interceptor contract.
- Endpoint isolation contract MVP.
- Local audit event subset.

## Delegated Interfaces

- Full Vault admission API to Phase 3.
- Full scanner/detonator job schema to Phase 4.

## Acceptance Tests

Primary owns AT-001, AT-002, AT-003 basic local fixture containment; CT-002, CT-003, CT-007 endpoint workflows; OT-004 policy-cache behavior; PA-001 local redaction. Contributes endpoint fixtures to CT-001, CT-005, CT-006, CT-008, CT-009, CT-010, and CT-011 as assigned in GOAL-09 `primary-owner-test-matrix.md`.

## Deliverables

- Rust workspace bootstrap.
- CLI/shim MVP.
- Linux sandbox runner MVP.
- macOS beta containment report.
- Local policy/audit MVP.
- Fixture test harness.
- Phase completion report.

## Exit Gate

A developer can run protected npm and pip installs on Linux and receive deterministic allow, deny, warn, or break-glass-required outcomes with audit IDs. On macOS, the same workflows must report deterministic outcomes and clearly label the mode as `macOS beta containment`, `macOS telemetry/interception only`, or `macOS containment unavailable`.

## Risks Accepted

macOS strong isolation remains beta until Phase 2 validates the VM path. CI/high-risk macOS workflows fail closed unless policy explicitly permits beta containment for that workflow.
