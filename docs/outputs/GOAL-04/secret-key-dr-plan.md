# Secret, Key, And DR Plan

## Secret Lifecycle

- Create in approved secret manager.
- Encrypt at rest with KMS.
- Rotate on schedule and on compromise.
- Revoke immediately when service identity changes.
- Expire temporary credentials automatically.
- Audit all reads, writes, rotations, and revocations.

## Key Custody

AWS MVP uses KMS with envelope encryption for CAS metadata, evidence bundles, policy snapshots, and audit exports.

## Backup And Restore

| Data | Backup | RPO | RTO |
| --- | --- | --- | --- |
| Metadata/verdict DB | PITR/snapshots | 15 min | 4 hr |
| CAS promoted | Versioned S3 + replication | 15 min | 4 hr |
| Quarantine/evidence | Versioned S3 + retention lock where required | 1 hr | 8 hr |
| Policy | Versioned signed store | 15 min | 2 hr |
| Audit logs | Append-only replicated store | 15 min | 8 hr |

## Key Compromise

1. Freeze promotions.
2. Revoke affected credentials.
3. Rotate KMS/customer keys.
4. Re-encrypt sensitive metadata/evidence where needed.
5. Verify CAS digest integrity.
6. Notify affected customers if evidence or policy material was exposed.

