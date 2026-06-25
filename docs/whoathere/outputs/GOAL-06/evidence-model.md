# Evidence Model

## Evidence Bundle

```json
{
  "schema_version": 1,
  "admission_id": "adm_...",
  "artifact_digest": "sha256:...",
  "environment": "linux-ci",
  "process_tree_ref": "processes.json",
  "filesystem_events_ref": "fs.json",
  "network_events_ref": "network.json",
  "dns_events_ref": "dns.json",
  "import_events_ref": "import.json",
  "static_signals": [],
  "reason_codes": [],
  "redaction_status": "redacted"
}
```

## Capture Scope

- Process exec tree and exit codes.
- File read/write paths with sensitive path redaction.
- Network destination metadata, not full payloads.
- DNS query names with redaction for canary secrets.
- Import-time behavior summary.
- Suspicious guards/delays.

## Exclusions

No source code, raw secrets, full environment dumps, full filesystem snapshots, or full network payloads are routine evidence.

