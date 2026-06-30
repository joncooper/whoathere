# Phase 2 Goal: Advanced Cross-Platform Isolation

## Objective

Harden endpoint isolation and compatibility for macOS/Linux, including subprocess inheritance, network decision tables, cleanup guarantees, real package compatibility, and CI/container mode.

## Source ADRs And Inputs

- ADR-003 Linux isolation.
- ADR-004 macOS isolation.
- GOAL-03 endpoint contracts and operational plan.
- GOAL-08 secure update and telemetry boundaries.
- GOAL-09 macOS beta containment positioning, endpoint egress decision table, phase-gate scorecard, and primary-owner test matrix.

## Locked Product Decisions

- Linux strong isolation uses namespaces, seccomp, cgroups, and Landlock where available.
- macOS Phase 1 is beta containment; Phase 2 owns GA containment graduation or an explicit decision to remain beta.
- Endpoint Security is telemetry/backstop, not sole sandbox.
- Subprocesses inherit isolation.

## Scope

- Harden Linux sandbox profiles.
- Validate macOS VM-backed workflow for GA containment or document why macOS remains beta.
- Backstop telemetry for missed invocations.
- Cleanup tests for crashes/signals/timeouts.
- Compatibility matrix for native npm modules and Python sdists.
- Docker/CI mode.

## Non-Goals

- Vault production deployment.
- Advanced cloud detonation.
- Windows endpoint.

## Owned Interfaces

- Endpoint isolation contract full version.
- Endpoint network decision table.
- Endpoint report schema.
- Cleanup validation contract.

## Delegated Interfaces

- Vault admission to Phase 3.
- Full detonation evidence model to Phase 4.

## Acceptance Tests

Primary owns CT-004, CT-010, CT-011, AT-006 local platform split validation, and AT-007 local native extension validation as assigned by GOAL-09. Contributes to OT-004 where endpoint policy failure behavior is local.

## Deliverables

- Hardened Linux backend.
- macOS VM backend GA validation report or explicit beta-containment continuation decision.
- Backstop telemetry implementation plan.
- Real package compatibility report.
- Endpoint cleanup test suite.
- CI/container integration plan.

## Exit Gate

Endpoint protection has measured compatibility and containment guarantees for supported Linux workflows and either GA macOS containment evidence or explicit beta-containment limitations for macOS.

## Risks Accepted

Some packages needing arbitrary network during build may require manual review or policy exceptions.
