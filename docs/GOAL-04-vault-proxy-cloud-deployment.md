# GOAL-04: Vault Proxy, Cache, And Cloud Deployment

## Objective

Design WhoaThere Vault as a secure, high-performance registry proxy and cache with scan-before-serve package admission. Compare AWS, Cloudflare, and hybrid deployment paths.

## Required Proxy Behavior

- Serve npm registry-compatible metadata and tarballs.
- Serve PyPI Simple API-compatible project pages and artifact links.
- Store artifacts in quarantine on cache miss.
- Promote only approved blobs and generated metadata to the serving namespace through an atomic servable-generation commit.
- Preserve npm integrity and PyPI hash semantics.
- Fail closed for unavailable scanner, detonator, metadata DB, policy service, or ambiguous verdicts unless break-glass is explicitly authorized.
- Define request flows for cache hit, cache miss, auth failure, upstream failure, policy denial, manual review, break-glass, and rollback.
- Define HTTP status/error contracts, retryability, redaction, request signing, replay resistance, and rate limits.

## Required Authority Boundaries

Each AWS, Cloudflare, and hybrid ADR must state the authoritative system for:

- Secrets and service credentials.
- KMS/envelope encryption keys.
- CAS blobs.
- Cache entries.
- Package metadata and verdicts.
- Policy.
- Audit logs and evidence bundles.
- Deployment state and rollback metadata.

The hybrid ADR must explicitly describe trust boundaries, latency impact, failure modes, and which provider is the system of record for each item.

## AWS Planning Requirements

Plan these network planes:

- Serving plane: customer private subnet to interface VPC endpoint to Vault PrivateLink endpoint service to NLB to registry proxy.
- Fetch plane: restricted egress subnets through NAT and AWS Network Firewall.
- Detonation plane: isolated ephemeral workers with no internal network route, no reusable credentials, blocked metadata service access, and captured telemetry.

Plan these components:

- S3 content-addressed blob store.
- Metadata DB for package aliases, verdicts, provenance, yanked/deprecated state, dist-tags, and audit pointers.
- Queue/workflow orchestration for cache-miss admission.
- Network Firewall/domain allow rules for npm/PyPI upstream fetchers.
- Private hosted zones and route-table controls that prevent CI from bypassing Vault.
- KMS, IAM, VPC endpoints, logs, metrics, and multi-AZ deployment.
- Backup/restore, disaster recovery, RPO/RTO targets, and key compromise procedure.

## Cloudflare Planning Requirements

Plan and evaluate:

- Workers registry facade.
- R2 blob storage.
- Workers Cache for hot metadata/artifacts, including local data-center cache semantics.
- Queues, Workflows, and Containers for admission and heavier scan/detonation tasks.
- Cloudflare Tunnel and Zero Trust access.
- Workers VPC/private routing beta risk.
- Whether Cloudflare is edge/cache layer, full system of record, or hybrid access layer.
- Whether signed, digest-bound stale approved serving is safe when AWS validation is temporarily unreachable.

## CodeArtifact Baseline

Compare AWS CodeArtifact as a buy/build baseline. The key question is whether it can be used without exposing unscanned upstream packages before Vault policy approval. The comparison must result in a concrete baseline artifact if CodeArtifact remains referenced.

## Required Cache-Miss State Machine

The plan must define states and transitions for:

- Miss detected.
- Admission lock acquired or duplicate suppressed.
- Upstream metadata fetched.
- Artifact fetched into quarantine.
- Hash and signature/integrity validation.
- Static scan.
- Detonation.
- Verdict written only after mandatory evidence passes.
- Servable generation committed, denied, quarantined, or manual review.
- Old metadata invalidated or retained.
- Client notified or deterministic failure returned.
- Retry, abort, poison-entry handling, and circuit breaker activation.

All transitions must be idempotent and auditable.

## Required Fail-Closed Matrix

For Vault unavailable, CAS unavailable, metadata DB unavailable, cache unavailable, provider auth failure, policy engine failure, scanner failure, detonator failure, stale config, partial deploy, and rollback, define:

- User-visible result.
- HTTP status/error body.
- Retryability.
- Alert.
- Audit event.
- Whether break-glass can apply.
- Explicit prohibition on permissive fallback, stale secrets, unsigned payloads, or unaudited bypasses.

## Required Deliverables

- `vault-architecture.md`: registry proxy, cache, scan/detonation, metadata, and serving design.
- `ADR-005-aws-vault-deployment.md`: AWS-native deployment decision.
- `ADR-006-cloudflare-vault-deployment.md`: Cloudflare-native deployment decision.
- `ADR-007-hybrid-vault-deployment.md`: hybrid architecture decision.
- `ADR-011-vault-deployment-recommendation.md`: final recommendation with rejection rationale and revisit trigger.
- `authority-boundaries.md`: source-of-truth ownership for secrets, CAS, cache, metadata, policy, audit, and deployment state.
- `cache-and-storage-plan.md`: CAS object naming, metadata DB model, promotion workflow, and retention.
- `cache-miss-state-machine.md`: deterministic miss, admission, detonation, promotion, retry, and poison-entry behavior.
- `request-flow-diagrams.md`: happy path, cache hit, cache miss, auth failure, upstream failure, policy denial, rollback.
- `vault-fail-closed-matrix.md`: failure mode, user result, HTTP contract, retry, alert, audit, and break-glass behavior.
- `secret-key-dr-plan.md`: secret lifecycle, key custody, rotation, backup/restore, RPO/RTO, and compromise procedure.
- `first-miss-ux.md`: blocking install, prewarm/admission API, lockfile submission, and deterministic failure comparison.
- `performance-plan.md`: latency budget, throughput model, and benchmark plan for 1,000 concurrent CI jobs.

## Acceptance Criteria

- The plan proves scan-before-serve semantics for all supported package flows.
- Warm-cache delivery has a concrete latency and throughput target.
- Cold-miss behavior is deterministic and package-manager-compatible.
- AWS, Cloudflare, and hybrid options are compared with the same criteria.
- The plan identifies exactly where downstream CI/dev resources are isolated from public registries.
- The plan includes outage and fail-closed behavior for every Vault dependency.
- The plan names the authoritative owner for secrets, CAS blobs, cache entries, metadata, policy, audit logs, and deployment state in every deployment option.
- Cache-miss admission is idempotent, duplicate-suppressed, poison-entry aware, and auditable.
- Rollback cannot expose unscanned packages or bypass policy.
- Cold-miss production promotion is allowed only for artifact classes with complete minimum allow-verdict evidence profiles.

## Exit Gate

Do not select a production deployment architecture until ADR-005, ADR-006, ADR-007, and ADR-011 are complete and one option has explicit superiority for security, compatibility, cost, and operations.

## Suggested Subagents

- AWS network/security architect.
- Cloudflare platform architect.
- Registry protocol compatibility reviewer.
- Performance and caching reviewer.
