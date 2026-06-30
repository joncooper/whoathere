# GOAL-08: Operations, Privacy, And Reliability

## Objective

Define the operational, privacy, reliability, secure-update, and incident-response requirements for WhoaThere before implementation planning begins.

## Required Operations Areas

- Secure binary distribution for macOS and Linux.
- Code signing and notarization for macOS.
- Linux package formats and checksum/signature verification.
- Auto-update or managed update strategy.
- Vault deployment environments, promotion, rollback, and disaster recovery.
- Observability: logs, metrics, traces, audit events, scanner evidence, and SLOs.
- Tenant/project isolation.
- Incident response for malicious package detection, false positives, proxy outage, and policy misconfiguration.
- Backup/restore for metadata DB, policy, audit logs, and object storage.

## Required Privacy Boundaries

The plan must avoid collecting:

- Source code.
- Secrets and tokens.
- Full environment dumps.
- Full network payloads.
- Complete filesystem contents.

Permitted by default:

- Package names, versions, ecosystems, artifact digests, source registries, lockfile metadata, policy decisions, scanner verdicts, and redacted evidence summaries.

Any exception requires explicit justification, retention limit, redaction strategy, and customer-visible policy.

## Required Reliability Defaults

- CI and high-risk installs fail closed on scanner/proxy/policy outage.
- Developer-machine warning mode may apply only to previously approved digest-bound artifacts within a signed TTL.
- Break-glass is time-bound, scoped, auditable, and revocable.
- Vault warm-cache path has an SLO distinct from cold-miss admission.
- Detonation queue backlog has alerting and admission behavior.
- Package promotion is atomic from client perspective.
- Minimum safe control-plane API/UX is required for enterprise launch even if dashboard polish is deferred.

## Required Deliverables

- `operations-plan.md`: environments, deployment, rollback, runbooks, and on-call responsibilities.
- `privacy-data-map.md`: collected data, purpose, retention, storage, redaction, and access controls.
- `secure-update-plan.md`: signing, notarization, package distribution, and update verification.
- `observability-slo-plan.md`: service indicators, objectives, alerts, dashboards, and evidence retention.
- `incident-response-plan.md`: malicious package, false positive, outage, and customer escalation playbooks.
- `ADR-010-telemetry-boundaries.md`: telemetry and evidence collection decision.
- `minimum-control-plane-plan.md`: policy, break-glass, manual review, audit, privacy export/delete, notifications, and admin identity requirements.

## Acceptance Criteria

- No required workflow depends on collecting source code, secrets, or full network payloads.
- Operators can distinguish warm-cache latency, cold-miss latency, scanner backlog, and policy-service failures.
- Rollback plans do not bypass scan-before-serve or fail-closed behavior.
- Secure update and signing requirements are defined before endpoint implementation.
- Incident-response workflow includes package quarantine and customer notification requirements.
- Phase 3 enterprise planning has concrete retention classes, export/delete behavior, and minimum control-plane workflows.

## Exit Gate

Do not begin production deployment planning until privacy boundaries, SLOs, secure updates, and incident-response paths are approved.

## Suggested Subagents

- SRE reviewer.
- Privacy/security compliance reviewer.
- Release engineering reviewer.
