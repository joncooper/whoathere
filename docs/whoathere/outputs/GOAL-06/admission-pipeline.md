# Admission Pipeline

## Invariant

No artifact becomes warm-cache content until its digest has an `allow` verdict for the relevant ecosystem metadata context, source context, evidence profile, and policy version.

## Pipeline

1. Receive npm or PyPI request from Vault.
2. Resolve package metadata using ecosystem-correct semantics.
3. Fetch metadata and artifact into quarantine CAS.
4. Compute SHA-256 and preserve npm SRI or PyPI hash fragments.
5. Record origin URL, headers, timestamp, yanked/deprecated state, dist tags, wheel tags, platform markers, and source registry.
6. Run static scan.
7. Run provenance, reputation, release-diff, and anomaly checks.
8. Detonate artifact in required matrix.
9. Produce verdict with reason codes and evidence references.
10. Write verdict only if the artifact's minimum allow-verdict evidence profile is complete.
11. Promote only through the Vault servable-generation protocol.
12. Emit audit events for every state transition.

## Verdict Rules

- `allow`: promote digest and generated metadata only when all mandatory evidence jobs for the artifact/source/platform class passed.
- `deny`: do not promote; return deterministic deny.
- `quarantine`: do not promote; retain evidence.
- `manual_review`: do not promote; route to reviewer.
- `inconclusive`: do not promote; route to manual review or retryable failure by policy.

GOAL-09 `minimum-allow-verdict-research-contract.md` owns the required downstream research table for exact artifact-class evidence.
