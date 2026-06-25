# Audit Schema

## Event Shape

```json
{
  "schema_version": 1,
  "event_id": "evt_...",
  "correlation_id": "corr_...",
  "timestamp": "RFC3339",
  "component": "cli|vault|worker|policy|admin",
  "environment": "developer|ci|container|detonation|admin",
  "actor": {"type": "user|machine|ci_runner|service", "id": "redacted-or-stable-id"},
  "tenant": "tenant-id",
  "project": "project-id",
  "package": {
    "ecosystem": "npm|pypi",
    "name": "package",
    "version": "1.2.3",
    "source": "registry-url",
    "digest": "sha256:...",
    "dependency_path": []
  },
  "policy": {"version": "2026-06-25.1", "rule_id": "rule", "decision": "deny"},
  "reason_codes": ["lifecycle_network_exfil"],
  "evidence_refs": ["s3://.../bundle.json"],
  "redaction_status": "redacted",
  "retention_class": "security"
}
```

## Rules

- Events are append-only.
- Evidence is referenced, not embedded.
- Source code, secrets, full env dumps, full payloads, and filesystem snapshots are not routine audit fields.
- Every allow, deny, quarantine, manual review, and break-glass action emits an event.

