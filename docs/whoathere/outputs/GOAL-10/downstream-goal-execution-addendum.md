# Downstream Goal Execution Addendum

Every downstream implementation-planning goal must read GOAL-09 before writing plans. The following items are not optional:

| Area | Required source | Non-negotiable handoff |
| --- | --- | --- |
| Release gates | GOAL-09 `phase-gate-scorecard.md` | Plans must produce owner, evidence, environment, threshold, approver, and fail-safe for their gate. |
| Test ownership | GOAL-09 `primary-owner-test-matrix.md` | Plans must use primary owner assignments and may list contributors separately. |
| Local schemas | GOAL-09 `interface-schema-contracts.md` | Phase 1 and Phase 3 must turn planning contracts into versioned schemas. |
| Endpoint egress | GOAL-09 `endpoint-egress-decision-table.md` | CI/high-risk direct public registry/index egress must be blocked before execution. |
| macOS | GOAL-09 `macos-beta-containment-positioning.md` | Phase 1 is beta containment; Phase 2 owns GA graduation. |
| Vault promotion | GOAL-09 `vault-promotion-rollback-data-model.md` | Phase 3 must implement servable-generation promotion and rollback. |
| Allow verdicts | GOAL-09 `minimum-allow-verdict-research-contract.md` | Phase 3/4 must answer artifact-class evidence profiles before production cold-miss promotion. |
| Outage/break-glass | GOAL-09 `outage-break-glass-hardening.md` | Unknown/unscanned artifacts cannot be installed, promoted, or served through outage/warn/break-glass paths. |
| Cloudflare hybrid | GOAL-09 `cloudflare-stale-approved-artifact-policy.md` | Stale serving requires signed digest-bound metadata and bounded TTL. |
| Operations | GOAL-09 `operations-launch-readiness-addendum.md` | Minimum control-plane API/UX is required for enterprise launch. |

## Do Not Re-Decide

- Rust is the default implementation language unless a benchmark trigger fires.
- AWS-only is the MVP Vault architecture.
- Cloudflare-only remains rejected for MVP.
- macOS Phase 1 is beta containment.
- Phase 3 cold-miss promotion is allowed only after the minimum allow-verdict contract is complete for that artifact class.
- Break-glass cannot promote unknown or unscanned code.

