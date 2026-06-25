# Vault Promotion And Rollback Data Model

## Core Invariant

An artifact is servable only when one servable generation binds all of:

- tenant/project/source context
- ecosystem, package, version, artifact type
- artifact digest
- metadata context digest
- policy version
- evidence profile and evidence bundle IDs
- verdict
- promotion transaction ID

The serving path must never trust an allow verdict that is not joined to a promoted CAS object and current servable generation.

## Required Tables Or Logical Stores

| Store | Purpose | Key fields |
| --- | --- | --- |
| `admission_request` | Deduplicate and track client requests. | `request_id`, `tenant_id`, `ecosystem`, `package`, `version`, `source`, `policy_version`, `state`. |
| `admission_attempt` | Preserve retries and failure reasons. | `attempt_id`, `request_id`, `worker_id`, `state`, `started_at`, `ended_at`, `failure_class`. |
| `artifact_blob` | CAS object identity. | `digest`, `size`, `media_type`, `storage_uri`, `integrity_status`. |
| `metadata_snapshot` | Immutable package metadata context. | `metadata_digest`, `ecosystem`, `package`, `source`, `fetched_at`, `provider_etag`. |
| `evidence_bundle` | Redacted evidence summary. | `bundle_id`, `artifact_digest`, `jobs`, `signals`, `redaction_status`. |
| `verdict` | Decision bound to evidence and policy. | `verdict_id`, `artifact_digest`, `metadata_digest`, `policy_version`, `decision`, `expires_at`. |
| `servable_generation` | Single serving pointer. | `generation_id`, `alias_key`, `artifact_digest`, `metadata_digest`, `verdict_id`, `active_from`, `active_until`. |
| `alias` | Registry/package-manager route. | `tenant_id`, `ecosystem`, `package`, `version`, `source`, `active_generation_id`. |

## Promotion Protocol

1. Fetch provider metadata and artifact into quarantine.
2. Verify provider integrity, lockfile hash if present, media type, and computed digest.
3. Create immutable `artifact_blob` and `metadata_snapshot` records with `integrity_status=verified`.
4. Run required scanner/detonator jobs for the artifact evidence profile.
5. Write `verdict=allow` only if every mandatory evidence job passes and policy allows the source/context.
6. Create `servable_generation` in the same conditional transaction that points the alias to the generation.
7. Serve only by resolving alias to active generation, then verifying verdict, digest, metadata digest, tenant/source context, and CAS object.

No client-visible allow response is valid until step 6 commits.

## Failure States

| State | Meaning | Client behavior |
| --- | --- | --- |
| `FetchFailed` | Provider fetch failed or rate-limited. | 503 or pending retry; no promotion. |
| `IntegrityFailed` | Digest, lockfile, or provider integrity mismatch. | 409/deny/quarantine. |
| `ScanFailed` | Scanner infrastructure failed. | 503/manual_review; no promotion. |
| `DetonationTimedOut` | Required detonation did not complete. | 503/manual_review; no promotion. |
| `EvidenceInconclusive` | Evidence did not prove allow. | manual_review/quarantine; no promotion. |
| `Poisoned` | Package/version/source should not retry automatically. | deny/quarantine. |
| `LockExpired` | Admission owner died. | Retry via new attempt; no serving. |
| `PromotionCommitted` | Generation pointer committed. | Servable if policy still allows. |

## Rollback Protocol

- Rollback changes active alias pointers to a previous approved generation.
- Rollback never creates a new allow verdict.
- Rollback never points to quarantine CAS.
- Rollback never serves an artifact whose verdict schema or policy version is unreadable.
- If the previous generation cannot be verified, Vault returns 503/deny by policy instead of serving.

## Tenant And Source Scoping

CAS blobs may be physically shared by digest, but metadata snapshots, verdicts, aliases, and servable generations must be scoped by tenant, project/workspace where applicable, source registry/index, ecosystem, package, and policy version. Public and private namespaces cannot share aliases.

