# Outage And Break-Glass Hardening

## Developer Outage Semantics

`developer_on_outage: warn` is replaced by narrower semantics:

| Policy value | Meaning |
| --- | --- |
| `block` | Block when Vault/policy/scanner state is unavailable. |
| `allow_approved_stale` | Allow only a previously approved digest-bound artifact within TTL and policy context. |
| `warn_approved_stale` | Same as `allow_approved_stale`, but prints a warning and emits audit event. |

No developer outage setting may allow an unknown digest, source conflict, internal namespace conflict, direct public fallback, scanner ambiguity, or policy ambiguity.

## CI And High-Risk Semantics

- CI and high-risk installs fail closed on Vault, policy, scanner, detonator, provider, or egress ambiguity.
- CI may use stale approved artifacts only if the artifact digest, metadata context, source, tenant, and policy version are still inside a signed validity window.
- CI cannot use developer warning semantics.

## Break-Glass Allowed Uses

- Temporarily allow a known approved digest whose policy changed unexpectedly.
- Temporarily route around a non-security operational issue for already approved artifacts.
- Temporarily unblock a specific package/source/digest after named security approver review.

## Break-Glass Prohibitions

Break-glass cannot:

- Promote an unknown or unscanned artifact.
- Convert scanner/detonator failure into allow.
- Enable public registry/index fallback for protected namespaces.
- Suppress audit emission.
- Apply to an unbounded package namespace.
- Persist longer than its expiry.
- Apply after revocation.
- Serve CAS objects with digest or metadata mismatch.

## Required Audit Events

Every break-glass lifecycle event must emit:

- `break_glass.requested`
- `break_glass.approved`
- `break_glass.used`
- `break_glass.expired`
- `break_glass.revoked`

Each event must include actor, approver where applicable, scope, reason, expiry, policy version, digest/source constraints, and evidence references.

