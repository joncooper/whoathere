# Privacy Data Map

## Collected By Default

| Data | Purpose | Retention | Storage |
| --- | --- | --- | --- |
| Package name/version/ecosystem | Policy and audit | customer policy | metadata DB |
| Artifact digest/source registry | Admission and integrity | package retention | metadata DB |
| Lockfile metadata | Prewarm and decision explanation | customer policy | metadata DB |
| Policy decision/reason | Audit and explainability | audit retention | audit store |
| Redacted evidence summary | Security review | evidence retention | object store |
| Correlation IDs | Debug/audit linkage | audit retention | audit store |

## Not Collected By Default

- Source code.
- Secrets and tokens.
- Full environment dumps.
- Full network payloads.
- Complete filesystem contents.

## Redaction

Token-like values, home paths, canary secrets, and credential filenames are redacted before storage. Raw evidence buffers are not persisted unless a future explicit customer-approved policy is designed.

## Customer Rights

Data inventory, export, and deletion plans are Phase 3 control-plane requirements.

Phase 3 must define retention classes and default durations, deletion exceptions and legal hold behavior, customer export format, tenant boundary validation, audit export behavior, evidence redaction review, and a field-level allowlist for persisted telemetry.
