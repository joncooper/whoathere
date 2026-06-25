# Interface Schema Contracts

These are planning contracts, not final wire schemas. Downstream goals must convert each section into versioned JSON Schema, OpenAPI, Protobuf, or Rust type definitions before implementation.

## Local Config Contract

Required file locations:

- Project: `.whoathere/config.toml`
- User: `$XDG_CONFIG_HOME/whoathere/config.toml` or platform equivalent.
- CI: explicit `WHOATHERE_CONFIG` path.

Required fields:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Semver-compatible config schema. |
| `mode` | enum | yes | `observe`, `beta_containment`, `protected`, `ci_fail_closed`. |
| `ecosystems` | map | yes | npm and pip source/policy settings. |
| `vault.url` | URL | optional for local-only | Required for Vault-backed mode. |
| `policy.snapshot_path` | path | yes | Signed local policy cache. |
| `policy.max_stale_seconds` | integer | yes | Must be zero or small in CI. |
| `outage.developer_on_outage` | enum | yes | `block`, `allow_approved_stale`, or `warn_approved_stale`; never means unknown allow. |
| `break_glass.enabled` | boolean | yes | CI may disable entirely. |
| `telemetry.level` | enum | yes | `off`, `local`, `redacted_remote`. |
| `macos.containment` | enum | yes on macOS | `beta_vm`, `telemetry_only`, `disabled`; no GA label in Phase 1. |

Required precedence:

1. Explicit CLI flags.
2. CI environment variables approved by policy.
3. Project config.
4. User config.
5. Built-in fail-closed defaults.

## Endpoint Event Contract

Required additional fields beyond GOAL-03:

| Field | Type | Purpose |
| --- | --- | --- |
| `schema_version` | string | Evolution and validation. |
| `event_kind` | enum | `intercept`, `policy_decision`, `egress_attempt`, `sandbox_start`, `sandbox_end`, `cleanup`, `bypass_detected`. |
| `execution_mode` | enum | `observe`, `beta_containment`, `protected`, `ci_fail_closed`. |
| `containment_backend` | enum | `linux_namespace`, `linux_container`, `macos_vm_beta`, `none`. |
| `containment_strength` | enum | `strong`, `beta`, `telemetry_only`, `failed_closed`. |
| `bypass_signal` | enum | `none`, `absolute_binary`, `python_module`, `nested_package_manager`, `direct_registry_egress`, `unknown`. |
| `redaction_result` | enum | `clean`, `redacted`, `field_dropped`, `event_dropped`, `quarantined`. |
| `decision_source` | enum | `local_policy`, `vault`, `break_glass`, `cached_approved_digest`, `default_fail_closed`. |

## Vault Admission API Contract

Required endpoints:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/v1/admission/requests` | POST | Submit or deduplicate a package admission request. |
| `/v1/admission/requests/{id}` | GET | Read admission status and evidence summary. |
| `/v1/verdicts/{ecosystem}/{package}/{version}` | GET | Resolve servable verdict and digest under policy context. |
| `/v1/artifacts/{digest}` | GET | Serve promoted CAS artifact only after verdict/metadata validation. |

Admission request required fields:

- `schema_version`
- `tenant_id`
- `workspace_id`
- `ecosystem`
- `package_name`
- `version_or_range`
- `source_type`
- `source_url_or_registry`
- `resolved_metadata_digest`
- `requested_platforms`
- `policy_version`
- `lockfile_context`
- `requester_identity`
- `ci_context`
- `required_evidence_profile`

Allowed responses:

| Code | Meaning |
| --- | --- |
| 200 | Existing approved verdict and promoted digest are servable. |
| 202 | Admission accepted or in progress; no unapproved serving. |
| 403 | Policy deny. |
| 404 | Unknown package/version/source under current policy. |
| 409 | Conflicting source, digest, namespace, or policy context. |
| 423 | Manual review or quarantine lock. |
| 503 | Vault/scanner/detonator dependency unavailable; no fail-open. |

## Scanner/Detonator Job Contract

Required fields:

- `job_id`
- `admission_request_id`
- `artifact_digest`
- `ecosystem`
- `artifact_type`
- `source_type`
- `platform_target`
- `evidence_profile`
- `network_policy`
- `filesystem_policy`
- `timeout_seconds`
- `retry_policy`
- `policy_version`
- `redaction_profile`

Terminal results:

- `passed`
- `failed_malicious`
- `failed_integrity`
- `inconclusive`
- `timed_out`
- `worker_failed`
- `manual_review_required`

Only `passed` may contribute to `allow`, and only when the artifact-specific evidence profile says all mandatory jobs passed.

## Evidence Bundle Contract

Required fields:

- `evidence_bundle_id`
- `artifact_digest`
- `metadata_context_digest`
- `policy_version`
- `jobs`
- `signals`
- `redaction_summary`
- `retention_class`
- `manual_review_refs`

Redaction failure behavior:

| Condition | Behavior |
| --- | --- |
| Secret detected in event field | Redact or drop field. |
| Redaction uncertain in non-critical field | Drop field and preserve redaction note. |
| Redaction uncertain in critical evidence | Quarantine evidence; do not persist raw value; route to manual review if needed. |
| Redaction system unavailable | Block remote persistence; local short-lived buffer only if encrypted and policy allows. |

