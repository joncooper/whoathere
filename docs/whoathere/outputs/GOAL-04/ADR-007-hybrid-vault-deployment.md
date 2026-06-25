# ADR-007: Hybrid Vault Deployment

- Status: accepted as optional extension
- Date: 2026-06-25

## Context

Hybrid deployment can combine AWS source-of-truth and detonation with Cloudflare edge access, Zero Trust, and cache economics.

## Decision

Use AWS as source of truth and Cloudflare only as a non-authoritative edge/access layer:

- AWS owns admission, verdicts, CAS source-of-truth, policy, audit, and deployment state.
- Cloudflare may front approved metadata/artifact responses, enforce Zero Trust access, and route private access via Tunnel where appropriate.
- Cloudflare cache entries are disposable and revalidated against AWS verdict/digest state.
- Cloudflare may serve stale approved artifacts during AWS control-plane unreachability only when a signed, digest-bound cache metadata record is valid and within `max_stale_until`.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Split metadata in Cloudflare and verdicts in AWS | Split-brain risk. |
| Cloudflare authoritative cache with AWS workers | Cache eviction/locality unsuitable for approval truth. |
| AWS-only forever | Loses potential edge latency and access benefits. |

## Authority Boundaries

AWS authoritative: secrets, keys, CAS, metadata, verdicts, policy, audit, evidence, deployment state. Cloudflare authoritative only for edge access configuration and disposable cache state.

## Security Impact

Preserves AWS scan-before-serve and private detonation while allowing Cloudflare Access/Tunnel controls. Stale serving cannot create approval, promote artifacts, extend verdicts, or serve unsigned/unapproved content.

## Operational Impact

Adds cache invalidation, signed edge metadata, stale-window enforcement, purge ordering, and edge config operations. Requires strict no-split-brain runbooks.

## Compatibility Impact

Improves non-AWS access and global warm-cache delivery once validated.

## Cost/Performance Impact

Potentially reduces egress and latency; adds operational complexity.

## Revisit Trigger

Use hybrid only after AWS-only semantics pass correctness tests and Cloudflare cache revalidation plus signed stale-approved serving are proven.
