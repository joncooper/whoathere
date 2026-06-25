# Endpoint Contracts

## Interceptor Request

Required fields:

- `schema_version`
- `correlation_id`
- `observed_command`
- `argv`
- `cwd`
- `platform`
- `user_id_hash`
- `machine_id`
- `parent_process`
- `real_binary_path`
- `env_redaction_summary`
- `package_context`
- `policy_mode`

## Isolation Contract

GOAL-09 `endpoint-egress-decision-table.md` is the source of truth for workflow-by-workflow network decisions. The rules below are the default target constraints.

| Area | Rule |
| --- | --- |
| Environment | Allow minimal package-manager env; redact token-like values; deny cloud credential exposure by default in sandbox. |
| Filesystem | Project, package cache, and temp writable; home and credential paths read-denied unless policy allows. |
| DNS | Deny by default in detonation; endpoint install allows only Vault/private registry policy targets. |
| Direct IP | Deny unless exact CIDR allow rule exists. |
| Localhost/private network | Deny by default; allow only explicit project policy. |
| Cloud metadata IPs | Always deny. |
| Git SSH/HTTPS | Deny in CI unless source allowlisted; developer prompt/warn by policy. |
| Subprocesses | Must inherit cgroup/namespace/VM/proxy policy and correlation ID. |
| Cleanup | VM/session, namespaces, mounts, sockets, temp dirs, credentials, and firewall/proxy state removed on success, failure, timeout, crash, or signal. |

## Protected-Context Bypass Contract

- CI/high-risk contexts must block direct public npm/PyPI egress before package-manager execution begins.
- `python -m pip`, venv Python, absolute Python paths, absolute npm/pip binaries, and nested package-manager invocations must be intercepted or fail closed in protected contexts.
- A bypass detected in `ci_fail_closed` mode is a policy violation, not warn-only telemetry.
- `whoathere doctor` must verify PATH order, real binary discovery, shim health, policy snapshot validation, Vault route, and egress enforcement.

## Event Schema

Required fields:

- `event_id`
- `correlation_id`
- `timestamp`
- `component`
- `platform`
- `process_tree`
- `command`
- `ecosystem`
- `package`
- `version_or_range`
- `source_type`
- `network_target`
- `matched_rule`
- `decision`
- `exit_code`
- `redaction_status`
- `execution_mode`
- `containment_backend`
- `containment_strength`
- `bypass_signal`

## Report Contract

Human output must include command, decision, reason, remediation, and audit ID.

JSON output must include all event fields plus `policy_version`, `evidence_refs`, and `retryable`.
