# Manual Review Workflow

## States

- `queued`
- `in_review`
- `approved`
- `denied`
- `needs_more_evidence`
- `expired`

## Reviewer Inputs

- Package coordinates and digest.
- Static signal summary.
- Detonation evidence summary.
- Version diff and maintainer/provenance signals.
- Policy rule and reason codes.
- Requested scope and affected projects.

## Decisions

- Approve only by digest and metadata context.
- Deny with reason codes.
- Request expanded detonation matrix.
- Create follow-up signature/provenance rule.

## Audit

Every review action records reviewer identity, timestamp, rationale, policy version, digest, and evidence references.

