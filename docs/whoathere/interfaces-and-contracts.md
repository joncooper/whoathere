# Interfaces And Contracts To Specify

This file is the contract checklist for the child planning goals. Each item must be owned by one goal and resolved before implementation planning starts.

GOAL-09 `outputs/GOAL-09/interface-schema-contracts.md` now provides concrete planning contracts for local config, endpoint events, Vault admission, scanner/detonator jobs, and evidence bundles. Downstream implementation plans must convert those contracts into versioned schemas before build work.

## CLI Commands

Required commands:

- `whoathere init`
- `whoathere doctor`
- `whoathere status`
- `whoathere protect npm -- <args>`
- `whoathere protect pip -- <args>`
- `whoathere policy check`
- `whoathere policy explain <decision-id>`
- `whoathere cache prewarm <lockfile-or-requirements>`
- `whoathere audit tail`
- `whoathere break-glass request`
- `whoathere break-glass revoke`
- `whoathere shim install`
- `whoathere shim uninstall`

Required exit-code classes:

- Success.
- Policy deny.
- Quarantine/manual review.
- Unsupported workflow.
- Local sandbox failure.
- Vault unavailable.
- Scanner/detonator unavailable.
- Break-glass required or expired.
- Internal error.

## Local Configuration

Specify a versioned config schema for:

- Tenant/project identity.
- Vault URL and registry/index endpoints.
- Local policy path and cache path.
- Shim enablement and real binary discovery.
- npm and pip steering behavior.
- Sandbox backend selection.
- Developer prompt/warn/block behavior.
- Offline and break-glass behavior.
- Redaction and telemetry settings.

## Endpoint Interceptor Contract

Specify:

- Observed command, argv, environment redaction policy, working directory, parent process, user, machine, platform, and real binary path.
- Package context when known: ecosystem, package name, version/range, lockfile path, dependency source type, and registry/index.
- Process-tree correlation, child-process inheritance rules, and signal/exit-code propagation.
- Decision result, failure reason, policy reference, and audit event ID.

## Endpoint Isolation Contract

Specify:

- Environment variable allow/redact/deny rules.
- DNS behavior.
- Proxy/firewall behavior.
- Direct IP, localhost, private network, and Git SSH/HTTPS behavior.
- Filesystem read/write mounts or shares.
- Subprocess inheritance.
- Cleanup guarantees for VMs, namespaces, helper processes, firewall rules, sockets, mounts, temp files, and credentials.

## Policy Schema

Specify:

- Versioning and validation.
- Subjects, resources, actions, conditions, and decisions.
- Internal namespace rules.
- Registry source rules.
- Lifecycle/build/import execution rules.
- Network egress rules.
- Lockfile and source-type rules.
- Override and break-glass rules.
- Fail-closed defaults.

## Audit Event Schema

Specify:

- Event ID, correlation ID, timestamp, component, and environment.
- Actor, machine, CI runner, project, tenant.
- Ecosystem, package, version, source, digest, dependency path.
- Policy version, verdict, reason codes, and evidence references.
- Scanner/detonator job IDs and summaries.
- Redaction status and retention class.

## Vault Admission API

Specify endpoints for:

- Submit package/artifact for admission.
- Query verdict by ecosystem/name/version/digest.
- Prewarm from lockfile or requirements file metadata.
- Fetch evidence summary.
- Request manual review.
- Request/revoke break-glass.
- Health, readiness, and dependency state.

Specify HTTP semantics for:

- Policy denial.
- Quarantine/manual review.
- Cache miss pending admission.
- Scanner/detonator unavailable.
- Vault degraded or unavailable.
- Retryable versus non-retryable failures.
- Break-glass required, active, expired, or revoked.

## Provider Authority Contract

For AWS-only, Cloudflare-only, and hybrid plans, specify the authoritative system for:

- Secrets.
- KMS/encryption keys.
- CAS objects.
- Cache entries.
- Package metadata.
- Verdicts.
- Policies.
- Audit logs.
- Evidence bundles.
- Deployment state.

## Secret And Key Lifecycle

Specify:

- Secret creation, encryption, rotation, revocation, expiration, and audit.
- KMS or provider-specific key custody.
- Envelope encryption rules.
- Recovery limits and key compromise procedure.
- Backup/restore requirements and RPO/RTO targets.

## Registry Compatibility

npm compatibility must specify:

- Packument rendering.
- Dist-tag snapshot behavior.
- Tarball URL rewriting.
- Integrity preservation.
- Scoped registry behavior.
- Lockfile `resolved` host behavior.
- Alias, optional dependency, peer dependency, workspace, git, tarball, and direct URL policy.

PyPI compatibility must specify:

- PEP 503/691 Simple API behavior as selected by the plan.
- Normalized project names.
- File links and hash fragments.
- `Requires-Python`.
- Yanked files.
- Wheel tags and platform markers.
- Sdists, editable installs, direct references, extras, and environment markers.

## Scanner/Detonator Job Schema

Specify:

- Job ID, package coordinates, artifact digest, source metadata.
- Requested detonation environment.
- Time, CPU, memory, process, filesystem, and network limits.
- Allowed egress mode.
- Evidence capture configuration.
- Verdict output and confidence/reason codes.
- Retry, timeout, and failure semantics.

## Cache Object Naming

Specify:

- Quarantine object keys by digest.
- Promoted object keys by digest.
- Ecosystem alias tables for npm and PyPI.
- Metadata snapshot versioning.
- Evidence bundle storage.
- Retention and garbage-collection rules.

## Override And Break-Glass

Specify:

- Who can request, approve, revoke, and audit.
- Scope by package, version, digest, project, user, machine, and time.
- Maximum duration.
- Required reason.
- Required notifications.
- How decisions appear in CLI and Vault audit logs.
