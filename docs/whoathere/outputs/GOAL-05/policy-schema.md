# Policy Schema

## Versioning

Policies use `schema_version: 1` and signed `policy_version` identifiers. Endpoint and Vault reject unsigned policies in protected mode.

## Top-Level Shape

```yaml
schema_version: 1
policy_version: "2026-06-25.1"
tenant: "tenant-id"
defaults:
  ci_on_outage: deny
  developer_on_outage: warn_approved_stale
  unsupported_source_ci: deny
  unsupported_source_developer: manual_review
rules: []
break_glass:
  max_duration_minutes: 120
  require_approver: true
```

## Validation Rules

- Every rule has stable `id`, `when`, and `decision`.
- `break_glass` rules require scope, reason, expiry, actor, approver, and audit event.
- `allow` on package coordinates must include digest or trusted registry condition.
- Public fallback for internal namespace is invalid unless a rule explicitly maps the internal namespace to a public source.
- Outage defaults cannot be permissive for CI.
- `developer_on_outage` may be only `block`, `allow_approved_stale`, or `warn_approved_stale`.
- Developer outage behavior never allows unknown digests, source conflicts, internal namespace conflicts, scanner ambiguity, policy ambiguity, or direct public fallback.
- Break-glass cannot promote unknown or unscanned artifacts, convert scanner/detonator failure into allow, or enable public fallback.

## Decision Consistency

Policy evaluation library is shared by CLI and Vault through `policy-core`; same request model must produce same decision and reason codes.
