# Operations Launch-Readiness Addendum

## SLO And Alert Requirements

Phase 3 must define:

- availability SLO for warm-cache metadata and artifact serving
- p95 and p99 latency targets
- error budget and burn-rate alerts
- scanner/detonator backlog thresholds
- promotion freeze alerts
- CI-impacting outage severity
- on-call owner and escalation path

Minimum starting targets to validate:

| Service area | Target to research/confirm |
| --- | --- |
| Warm metadata | p95 <= 150 ms, p99 target required. |
| Warm artifact first byte | p95 <= 250 ms, p99 target required. |
| 1,000 concurrent CI warm cache | Error rate and p99 threshold required before Phase 3. |
| Cold miss | No fixed latency SLO until evidence profile benchmarks; CI should prewarm. |

## Secure Update ADR Requirements

Before external endpoint distribution, produce an ADR covering:

- signing-key custody
- threshold signing or equivalent release approval
- manifest expiry
- rollback protection
- revocation and emergency kill switch
- channel promotion rules
- emergency release authority
- transparency/Sigstore/TUF-style metadata decision
- macOS signing/notarization and Linux package signing

## Incident Response Requirements

Phase 3/4 runbooks must define:

- SEV levels
- incident commander role
- escalation contacts
- customer notification triggers and SLAs
- package revocation workflow
- promotion freeze workflow
- rollback criteria
- evidence handling and privacy rules
- drill pass/fail criteria

## Privacy Lifecycle Requirements

Phase 3 control-plane planning must define:

- retention classes and default durations
- deletion exceptions and legal hold behavior
- customer export format
- tenant boundary validation
- audit export behavior
- evidence redaction review process
- field-level allowlist for persisted telemetry

## Minimum Control-Plane Research Contract

The minimum admin/control plane is a core research question. The downstream loop must define the smallest safe API/UX for:

- policy CRUD and validation
- namespace/source restrictions
- break-glass request, approval, use, expiry, revoke
- manual review queues and evidence summaries
- audit search/export
- privacy inventory/export/delete
- admin notifications
- tenant/user/service identity administration

Dashboard polish remains not-now. The API/UX needed to operate safely is not optional.

