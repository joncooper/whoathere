# ADR-011: Vault Deployment Recommendation

- Status: accepted
- Date: 2026-06-25

## Context

GOAL-04 compared AWS-only, Cloudflare-only, and hybrid deployment options for Vault.

## Decision

Select AWS-only as the MVP production architecture. Keep hybrid Cloudflare edge/access as a Phase 3+ optional extension. Reject Cloudflare-only for MVP.

## Decision Criteria

| Criterion | AWS-only | Cloudflare-only | Hybrid |
| --- | --- | --- | --- |
| Private VPC ingress | strong | immature/beta-dependent | strong via AWS source |
| Detonation isolation | strong | higher risk | strong via AWS source |
| Scan-before-serve authority | simple | possible but riskier | simple if AWS authoritative |
| Global latency | regional unless replicated | strong | strong later |
| Operational maturity | high but heavier | simpler but platform-limit risk | highest complexity |
| MVP risk | lowest | highest | medium |

## Rejection Rationale

Cloudflare-only is rejected because package detonation and private-network routing are central security requirements. Hybrid is rejected for MVP because it adds split-brain/cache-revalidation risk before the source-of-truth model is proven.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| AWS-only MVP | Selected. Best security and operational fit for hardened VPC/private detonation. |
| Cloudflare-only MVP | Rejected for MVP because private-network/detonation maturity is weaker for this use case. |
| Hybrid MVP | Rejected for MVP because it adds cache revalidation and authority-boundary complexity before AWS source-of-truth semantics are proven. |

## Security Impact

AWS-only MVP gives the clearest private ingress, controlled egress, isolated detonation, KMS, and scan-before-serve authority boundary.

## Operational Impact

AWS-only MVP is heavier to operate than Cloudflare-only, but has more mature primitives for VPC routing, firewalls, IAM, KMS, and isolated worker fleets.

## Compatibility Impact

AWS-only is strongest for AWS-hosted enterprise CI and private VPC consumption. Non-AWS and global edge access remain hybrid follow-up work.

## Cost/Performance Impact

AWS introduces NAT, firewall, PrivateLink, and regional serving costs. Hybrid Cloudflare can be revisited for edge latency and egress economics after AWS correctness gates pass.

## Revisit Trigger

Revisit after AWS MVP passes correctness/performance gates and Cloudflare edge cache can prove digest/verdict revalidation without serving stale or unapproved artifacts.
