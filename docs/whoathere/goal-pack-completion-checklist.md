# Goal Pack Completion Checklist

Use this checklist to decide whether a WhoaThere goal pack is genuinely complete. A goal pack is not done because prose exists; it is done only when its outputs are traceable, reviewable, and ready to hand to the next planning or implementation agent.

## Required Completion Evidence

For each goal pack, record:

- Goal ID and title.
- Output directory and produced files.
- Owner or executing agent.
- Date completed.
- Inputs consumed from earlier goal packs.
- Decisions made.
- Decisions deferred.
- New follow-up goals created.
- Risks accepted.
- Reviewers or subagents used.
- Readiness tier: `artifact_present`, `planning_ready`, `research_required`, `validation_pending`, or `implementation_ready`.

## Deliverable Traceability

Every item listed under the goal pack's `Required Deliverables` section must have:

- A produced file or explicit replacement artifact.
- A short completion note.
- A link to the relevant goal acceptance criteria.
- Any unresolved questions moved into a follow-up goal, not left inline as ambiguity.

If a deliverable is intentionally skipped, the completion record must state:

- Why it is not needed.
- What artifact replaces it.
- Which acceptance criteria remain satisfied.
- Who approved the deviation.

## Interface Traceability

Each goal pack must update or reference [interfaces-and-contracts.md](interfaces-and-contracts.md).

For every applicable interface, the completion record must state one of:

- `specified`: concrete enough for implementation planning.
- `owned_elsewhere`: delegated to another named goal pack.
- `not_applicable`: explicitly out of scope with rationale.

No interface may remain implicitly unowned.

Interfaces may be marked `research_required` only when a named downstream goal owns the research question, the blocking decision is explicit, and the current package states the fail-closed behavior until the research is complete.

## Test Traceability

Each goal pack must map its output to [acceptance-test-matrix.md](acceptance-test-matrix.md).

For every relevant test scenario, the completion record must state:

- Test ID.
- Planned fixture or validation method.
- Expected result.
- Owning phase or subsystem.
- Whether the current goal fully handles it or delegates it.

Security-critical scenarios must not be delegated without naming the downstream goal that owns them.

## ADR Validation

Every ADR produced by a goal pack must include:

- Status: proposed, accepted, rejected, or superseded.
- Date.
- Context.
- Decision.
- Alternatives considered.
- Security impact.
- Operational impact.
- Compatibility impact.
- Cost/performance impact where relevant.
- Revisit trigger.
- Rejection rationale for non-selected options.

Deployment ADRs must also state the authoritative owner for secrets, keys, CAS objects, cache entries, metadata, verdicts, policies, audit logs, evidence bundles, and deployment state.

## Exit-Gate Validation

Before declaring a goal pack complete, answer:

- Are all required deliverables present or explicitly replaced?
- Are all acceptance criteria satisfied?
- Is the exit gate satisfied verbatim?
- Are all interfaces owned?
- Are all relevant tests mapped?
- Are security/privacy/operations implications explicit?
- Are unresolved questions converted into follow-up goals?
- Would another engineer or agent be able to continue without asking what decision was intended?

If any answer is no, the goal pack remains incomplete.

## Readiness Tier Validation

Use these tiers consistently:

- `artifact_present`: a required artifact exists and captures intent.
- `planning_ready`: another agent can create implementation tasks without re-deciding product scope.
- `research_required`: a named downstream goal must answer the question before implementation readiness.
- `validation_pending`: the design is accepted but requires benchmark, compatibility, or security validation.
- `implementation_ready`: schemas, state transitions, tests, thresholds, and failure behavior are concrete enough to build.

The planning package may be globally complete at `planning_ready`. It must not call itself `implementation_ready` while allow-verdict criteria, control-plane APIs, or platform containment validation remain open.

## Completion Record Template

Copy this template into the goal output directory as `completion-record.md`.

```md
# Completion Record: GOAL-XX

## Summary

- Goal:
- Executing agent:
- Date:
- Output directory:
- Status: complete | incomplete | blocked
- Readiness tier: artifact_present | planning_ready | research_required | validation_pending | implementation_ready

## Produced Deliverables

| Required deliverable | Produced artifact | Status | Notes |
| --- | --- | --- | --- |

## Decisions

| Decision | Outcome | ADR or artifact | Revisit trigger |
| --- | --- | --- | --- |

## Interface Traceability

| Interface | Status | Owner/artifact | Notes |
| --- | --- | --- | --- |

## Test Traceability

| Test ID | Status | Owner/artifact | Notes |
| --- | --- | --- | --- |

## Acceptance Criteria

| Criterion | Evidence | Status |
| --- | --- | --- |

## Exit Gate

State whether the exit gate is satisfied, with evidence.

## Open Follow-Up Goals

| Follow-up goal | Reason | Blocking? |
| --- | --- | --- |

## Security, Privacy, And Operations Notes

Summarize material implications and accepted risks.
```

## Global Done Definition

The full WhoaThere goal-pack execution is complete only when:

- Every GOAL-01 through GOAL-08 has a `completion-record.md`.
- GOAL-09 has a `completion-record.md` if a remediation review has been run.
- Every required deliverable is present or explicitly replaced.
- Every ADR needed by the goal packs exists and has a status.
- Every interface in [interfaces-and-contracts.md](interfaces-and-contracts.md) is specified, owned elsewhere, or explicitly not applicable.
- Every test in [acceptance-test-matrix.md](acceptance-test-matrix.md) has an owning downstream phase or subsystem.
- GOAL-07 has produced the four downstream phase goals.
- The final output can be used to generate granular implementation plans for a working WhoaThere CLI and Vault without re-deciding product scope.
- The final output distinguishes artifact presence, planning readiness, validation pending, research required, and implementation readiness.
