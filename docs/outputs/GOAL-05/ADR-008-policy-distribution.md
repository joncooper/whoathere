# ADR-008: Policy Distribution

- Status: accepted
- Date: 2026-06-25

## Context

Endpoint and Vault must evaluate the same policy while supporting offline developer work and fail-closed CI.

## Decision

Use hybrid remote-managed policy with signed local caches:

- Policy service is authoritative.
- Endpoints cache signed policy snapshots with TTL.
- CI requires fresh policy or fails closed.
- Developer mode may use cached policy within TTL and warn on stale remote only if policy allows.
- GitOps export/import is supported for review, not as the runtime source of truth.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Local-only files | Weak enterprise control and audit. |
| Remote-only | Poor offline developer UX. |
| GitOps-only runtime | Slower revocation and less direct machine/CI identity binding. |

## Security Impact

Signed snapshots prevent local tampering. CI outage behavior remains fail closed.

## Operational Impact

Requires policy distribution, TTL, revocation, and cache inspection tooling.

## Compatibility Impact

Developers can work offline within signed TTL where policy allows.

## Cost/Performance Impact

Local evaluation avoids per-command remote dependency in normal developer mode.

## Revisit Trigger

Revisit if customers require GitOps as authoritative runtime source with equivalent signing/revocation.

