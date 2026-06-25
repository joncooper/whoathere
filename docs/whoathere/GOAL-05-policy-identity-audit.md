# GOAL-05: Policy, Identity, And Audit

## Objective

Define the policy, identity, verdict, override, and audit model that connects local endpoint decisions, Vault admission, admin intent, and security evidence.

## Required Policy Model

Policy subjects:

- User, machine, CI runner, project, repository, tenant, team, and service account.

Policy resources:

- Ecosystem, package name, version, artifact digest, source registry, dependency edge, lockfile entry, lifecycle script, build backend, native extension, and network destination.

Policy decisions:

- `allow`
- `deny`
- `quarantine`
- `manual_review`
- `break_glass`

Required policy areas:

- Internal namespace and package-name protections for dependency confusion.
- Public/private registry precedence.
- Lockfile mismatch behavior.
- Git, tarball, direct URL, editable, and local-path dependency behavior.
- Lifecycle script and build backend execution.
- Network egress during install/build/detonation.
- Import-time detonation requirements.
- CI fail-closed defaults.
- Developer-machine warning and prompt behavior, limited to previously approved digest-bound artifacts during outages.

## Required Identity And Trust Model

- Tenant/project hierarchy.
- Local user and machine identity.
- CI runner identity.
- Service identity for Vault components.
- Policy provenance and signing.
- Break-glass authorization identity, duration, reason, and audit evidence.
- Break-glass prohibitions: no unknown/unscanned artifact promotion, no scanner/detonator failure bypass for unknown digests, no public fallback, and no unaudited use.
- Offline/local mode behavior when remote policy is unavailable.

## Required Audit Model

Every allow, deny, quarantine, manual review, and break-glass action must produce an audit event with:

- Actor and subject.
- Package ecosystem, name, version, source, digest, and dependency path where known.
- Policy version and decision reason.
- Scanner/detonator verdict references.
- Network and filesystem evidence references where relevant.
- Environment classification: developer, CI, container, detonation, or admin action.
- Correlation IDs across CLI, Vault, workers, and admin workflows.

## Required Deliverables

- `policy-model.md`: subjects, resources, conditions, decisions, defaults, and examples.
- `policy-schema.md`: versioned policy schema and validation rules.
- `identity-model.md`: tenant/project/user/machine/CI/service identity design.
- `audit-schema.md`: append-only event schema and evidence references.
- `override-break-glass.md`: approval, duration, scope, revocation, and audit requirements.
- `ADR-008-policy-distribution.md`: local-first, remote-managed, GitOps, or hybrid policy distribution decision.

## Acceptance Criteria

- The same package request receives an explainable decision from both CLI and Vault.
- Break-glass cannot silently become a permanent allow rule.
- Internal package namespace protection is represented directly in policy.
- Policy can express fail-closed scanner/proxy outage behavior.
- Audit events do not require storing source code, secrets, or full network payloads.

## Exit Gate

Do not start control-plane or admin workflow planning until `policy-schema.md` and `audit-schema.md` are concrete enough for implementation tests.

## Suggested Subagents

- Policy language reviewer.
- Enterprise identity/security reviewer.
- Audit/compliance reviewer.
