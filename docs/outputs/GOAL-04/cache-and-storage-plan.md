# Cache And Storage Plan

## CAS Keys

- Quarantine: `quarantine/sha256/<first2>/<digest>`
- Promoted: `promoted/sha256/<first2>/<digest>`
- Evidence: `evidence/<admission_id>/<artifact_digest>/bundle.json`
- Metadata snapshots: `metadata/<ecosystem>/<normalized_name>/<snapshot_id>.json`

## Alias Tables

- npm: `name`, `version`, `dist_tag_snapshot`, `tarball_digest`, `integrity`, `source_registry`, `verdict_id`.
- PyPI: `normalized_name`, `filename`, `version`, `wheel_tags`, `requires_python`, `hashes`, `yanked`, `verdict_id`.
- Servable generation: `generation_id`, `tenant_id`, `ecosystem`, `package`, `version`, `source_registry`, `artifact_digest`, `metadata_digest`, `policy_version`, `verdict_id`, `active_from`, `active_until`.

## Integrity

- Compute SHA-256 for all artifacts.
- Preserve npm SRI and PyPI hash fragments.
- Verify digest on write and every read before serving.
- Tamper or mismatch creates deny/quarantine event and never serves content.

## Promotion

Promotion is atomic from the client perspective and implemented through a servable-generation commit:

1. Fetch into quarantine and verify artifact digest, provider integrity, and lockfile hash where present.
2. Create immutable artifact and metadata snapshot records.
3. Run mandatory evidence jobs for the artifact evidence profile.
4. Write allow verdict only if policy and all required evidence pass.
5. Create a `servable_generation` that joins artifact digest, metadata digest, policy version, verdict, tenant/source context, and evidence refs.
6. Publish or move the alias pointer to the servable generation in one conditional transaction.

No serving path may return an allow verdict unless the active servable generation, verdict, metadata, and CAS object all verify.

GOAL-09 `vault-promotion-rollback-data-model.md` owns the detailed implementation-planning model.

## Retention And GC

- Promoted artifacts retained while referenced by policy, lockfile snapshot, or active cache TTL.
- Quarantine denied artifacts retained per security evidence policy.
- Manual-review artifacts retained until review plus retention window.
- GC never deletes evidence before audit retention expires.
