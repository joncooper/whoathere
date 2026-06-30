# Cloudflare Stale Approved Artifact Policy

## Decision

Cloudflare hybrid may serve stale approved artifacts when AWS control-plane validation is temporarily unreachable, but only under a signed, digest-bound, non-authoritative cache contract. Cloudflare remains non-authoritative for verdicts, metadata, policy, evidence, audit truth, and CAS promotion.

## Required Cache Metadata

Every edge cache object must carry signed metadata:

- `artifact_digest`
- `metadata_context_digest`
- `ecosystem`
- `package`
- `version`
- `source_registry`
- `tenant_or_access_scope`
- `policy_version`
- `verdict_id`
- `generation_id`
- `issued_at`
- `expires_at`
- `max_stale_until`
- signature over all fields

## Serve Rules

| Condition | Edge behavior |
| --- | --- |
| AWS reachable and verdict/generation validates | Serve approved artifact or metadata. |
| AWS unreachable, signature valid, digest matches, within `max_stale_until` | May serve stale approved artifact if policy permits stale serving. |
| AWS unreachable, metadata endpoint request without signed stale metadata | 503; do not synthesize metadata. |
| Signature invalid or expired | 503 and purge candidate. |
| Digest mismatch | 503/quarantine signal; never serve. |
| Policy says no stale serving | 503. |
| Negative cache entry | May serve deny/manual_review only within signed negative-cache TTL. |

## Purge And Revalidation

- AWS remains the purge authority for core artifact decisions.
- Revocation events must purge matching generation IDs and policy versions.
- Edge must revalidate before extending stale windows.
- Edge cannot promote, override, or create verdicts.
- Edge stale serving must emit local edge logs and backfill AWS audit when connectivity returns.

## Validation Gate

Hybrid cannot be enabled until tests prove:

- stale approved artifacts do not serve past `max_stale_until`
- unapproved artifacts never serve from edge
- revoked generations purge or fail closed
- AWS-unreachable behavior matches policy
- cache poisoning cannot create signed metadata

