# GOAL-01: Product Scope, Threat Model, And MVP Workflow

## Objective

Create the authoritative product and threat-model scope for WhoaThere MVP. This goal decides what the first product version protects, what it intentionally does not protect, and how reviewers will judge whether later plans preserve the security intent.

## In Scope

- Protected workflows: `npm install`, `npm ci`, `npx`, `npm exec`, `pip install`, `pip3`, and `python -m pip`.
- Personas: developer laptop user, CI runner operator, security admin, and platform engineer.
- Attacks: dependency confusion, typo-squatting, lifecycle script abuse, malicious Python build hooks, data exfiltration, malicious native extensions, maintainer takeover, platform-specific payloads, lockfile/source bypasses, and delayed execution.
- Enforcement modes: block, warn, audit, quarantine, manual review, and break-glass.
- MVP boundaries for local-only mode, Vault-backed mode, and CI mode.

## Out Of Scope

- Full runtime application protection after package installation.
- Windows endpoint implementation.
- Browser extension, IDE plugin, and SaaS dashboard UI design.
- General vulnerability management outside package admission decisions.
- TLS interception of arbitrary developer traffic.

## Required Decisions

- Define the first protected vertical slice: local CLI only, Vault-backed CLI, or CI-first with Vault.
- Define when the product blocks versus warns for developer machines, CI, and security-admin policies.
- Define how unsupported workflows fail: allow with warning, deny, or require explicit break-glass.
- Define what information can be collected without capturing secrets or source code.
- Define the minimum malicious fixture set that every later plan must support.

## Required Deliverables

- `product-scope.md`: MVP thesis, personas, protected workflows, non-goals, and first vertical slice.
- `threat-model.md`: assets, trust boundaries, adversary capabilities, abuse cases, mitigations, and residual risk.
- `policy-posture.md`: block/warn/audit defaults by workflow and environment.
- `malicious-fixtures.md`: required fixture packages, expected behavior, and pass/fail criteria.
- `decision-log.md`: explicit decisions and deferred questions.

## Acceptance Criteria

- A reviewer can explain exactly what WhoaThere blocks, warns on, records, ignores, and defers.
- Every required test in the acceptance matrix is mapped to a threat-model entry.
- MVP scope includes both macOS and Linux endpoint planning while acknowledging asymmetric isolation strength.
- CI and high-risk install paths fail closed by default.
- The scope states that import-time detonation is in scope and full runtime protection is out of scope.

## Exit Gate

Do not proceed to architecture lock until `product-scope.md`, `threat-model.md`, and `policy-posture.md` agree on the same protected workflows and enforcement defaults.

## Suggested Subagents

- Product/security scope reviewer.
- Adversarial package author to expand fixture coverage.
- Developer-experience reviewer to identify workflows likely to break.

