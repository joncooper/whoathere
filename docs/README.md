# WhoaThere Build-Ready Goal Packs

This directory implements the WhoaThere meta-plan. It does not build the product yet. It defines the next set of executable planning goals that, when completed, should produce granular implementation plans for a deployable WhoaThere CLI and Vault.

## Locked Defaults

- Endpoints: macOS and Linux in parallel for the first planning track.
- Package managers: npm and pip first, with explicit coverage for `npm install`, `npm ci`, `npx`, `npm exec`, `pip install`, `pip3`, and `python -m pip`.
- Cloud targets: compare AWS, Cloudflare, and hybrid deployment paths.
- Deployment bias: AWS is the default for hardened VPC/private-network detonation unless the cloud comparison proves otherwise.
- Enforcement posture: fail closed for CI, high-risk installs, unsupported dependency source types, and scanner/proxy outages unless an explicit break-glass policy is active.
- Windows: document as a later expansion track, not part of the first endpoint delivery.
- Primary enforcement exclusions: do not make TLS MITM, `LD_PRELOAD`, `DYLD_*`, or WASM the primary enforcement model.
- Runtime scope: full application runtime protection is out of MVP scope; import-time detonation is in scope.

## Goal Execution Order

1. Run [GOAL-01 Product Scope, Threat Model, And MVP Workflow](GOAL-01-product-scope-threat-model.md).
2. Run [GOAL-02 System And Language Architecture](GOAL-02-system-language-architecture.md), [GOAL-03 Endpoint Interception And Isolation](GOAL-03-endpoint-interception-isolation.md), and [GOAL-04 Vault Proxy, Cache, And Cloud Deployment](GOAL-04-vault-proxy-cloud-deployment.md) in parallel after GOAL-01 inputs are available.
3. Run [GOAL-05 Policy, Identity, And Audit](GOAL-05-policy-identity-audit.md) and [GOAL-06 Detection And Detonation](GOAL-06-detection-detonation.md) after GOAL-02 through GOAL-04 have draft outputs.
4. Run [GOAL-08 Operations, Privacy, And Reliability](GOAL-08-operations-privacy-reliability.md) alongside GOAL-05 and GOAL-06.
5. Run [GOAL-07 Engineering Roadmap Goal Pack](GOAL-07-engineering-roadmap.md) last, using all prior outputs to generate the four downstream phase goals.
6. Run [GOAL-09 Remediation And Build-Readiness Hardening](GOAL-09-remediation-hardening.md) after review, before generating granular implementation goals.
7. Run [GOAL-10 Quality Hardening Passes](GOAL-10-quality-hardening-passes.md) after remediation when you need rubric-based verification and package-level quality hardening.

## Cross-Cutting Artifacts

- [Interfaces And Contracts](interfaces-and-contracts.md) lists every API, schema, command, and registry behavior the child plans must specify.
- [Acceptance Test Matrix](acceptance-test-matrix.md) defines the required adversarial, compatibility, outage, and performance scenarios.
- [Goal Pack Completion Checklist](goal-pack-completion-checklist.md) defines the evidence required before a goal pack can be declared done.
- [Execute All Goal Packs Prompt](execute-all-goal-packs-goal-prompt.md) contains a reusable `/goal` prompt for running the complete goal-pack execution.
- [Overnight Build And Implement Prompt](overnight-build-and-implement-goal-prompt.md) contains the `/goal` prompt for generating detailed build plans, running 3-5 quality passes, and starting implementation.
- [GOAL-09 Remediation](GOAL-09-remediation-hardening.md) captures the review-hardening pass that makes the package build-planning ready.
- [GOAL-10 Quality Hardening](GOAL-10-quality-hardening-passes.md) captures the three-pass rubric/evaluation/improvement/verification loop.

## Output Standard For Every Goal

Each goal must produce child-plan-ready artifacts with:

- Objective, scope, non-goals, and dependencies.
- Decisions made, decisions deferred, and ADRs for major choices.
- Concrete deliverables with exact filenames.
- Acceptance criteria and exit gates.
- Security, privacy, and operational implications.
- Test scenarios that map back to the acceptance matrix.
- Open questions converted into explicit follow-up goals, not left as prose.
- A readiness tier: `artifact_present`, `planning_ready`, `research_required`, `validation_pending`, or `implementation_ready`.

## Recommended Subagent Pattern

Use separate subagents for endpoint isolation, package-manager compatibility, cloud/network architecture, adversarial threat modeling, and operations review. The main agent remains responsible for integrating the outputs and resolving conflicts into one coherent goal result.
