# ADR-010: Telemetry Boundaries

- Status: accepted
- Date: 2026-06-25

## Context

WhoaThere needs enough telemetry to explain security decisions without collecting customer source code, secrets, or unnecessary payload data.

## Decision

Collect package metadata, artifact digests, source registries, decision metadata, policy versions, redacted evidence summaries, and correlation IDs. Do not collect source code, secrets/tokens, full environment dumps, full network payloads, or complete filesystem contents by default.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Full payload capture | Too invasive and high liability. |
| Source snapshot capture | Violates privacy boundary and not required for MVP. |
| Minimal counts only | Insufficient for audit, review, and explainability. |

## Security Impact

Reduces data-exfiltration blast radius if WhoaThere telemetry storage is compromised.

## Operational Impact

Evidence must be carefully structured and redacted before persistence.

## Compatibility Impact

No impact on package-manager compatibility.

## Cost/Performance Impact

Lower storage costs than full payload capture.

## Revisit Trigger

Only revisit for customer-approved advanced forensics mode with explicit retention and redaction controls.

