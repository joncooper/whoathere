# Release Gates

Detailed executable gates live in GOAL-09 `phase-gate-scorecard.md`. This file is the phase-level summary.

## Phase 1 Gate

- CLI/shim workflows pass Phase 1-owned tests from GOAL-09: CT-002, CT-003, CT-007, OT-004, and PA-001.
- Linux malicious npm and Python fixture basics pass AT-001 through AT-003.
- macOS ships only as beta containment unless Phase 2-level validation is already complete.
- Protected-context bypass guard proves CI/high-risk direct public registry/index egress is blocked before package-manager execution.
- Secure update ADR is complete before external endpoint distribution.

## Phase 2 Gate

- Linux sandbox containment tests pass.
- macOS VM-backed or accepted strong-isolation path validates GA containment or remains explicitly beta.
- Subprocess inheritance and cleanup pass CT-004, CT-010, CT-011.
- Compatibility matrix includes native npm modules and Python sdists.
- Endpoint telemetry respects ADR-010.

## Phase 3 Gate

- Vault scan-before-serve invariant passes for npm and PyPI artifact classes whose minimum allow-verdict profiles are complete.
- Cold-miss promotion uses atomic servable-generation protocol and cannot expose allow without promoted CAS/metadata.
- OT-001 through OT-008 pass.
- PT-001 through PT-004 benchmarks meet defined p95, p99, error-budget, and workload targets or block production use for the affected path.
- AWS rollback cannot serve unscanned packages.
- Policy/audit integration passes PA-002.
- Minimum control-plane API/UX research is complete for policy, break-glass, manual review, audit, privacy export/delete, and notifications.

## Phase 4 Gate

- Full malicious fixture suite AT-001 through AT-009 passes against detonation matrix.
- Manual review binds decisions to digest/context.
- Incident drills pass for malicious package, false positive, outage, policy misconfiguration, and key compromise.
- Multi-tenant privacy and audit boundaries validated.

## Global Gate

No release may permit public-registry fallback, unapproved artifact serving, unaudited break-glass, or routine collection of source/secrets/full payloads.

Developer outage warning mode is valid only for previously approved digest-bound artifacts inside TTL. Break-glass cannot promote unknown or unscanned artifacts, bypass scanner/detonator failure for unknown digests, or enable public fallback.
