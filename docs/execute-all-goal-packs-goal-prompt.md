# `/goal` Prompt: Execute All WhoaThere Goal Packs

Use this prompt with `/goal` to execute the goal packs in this directory and produce the full build-planning package.

```text
Execute the WhoaThere goal packs in /Users/jdc/src/whoathere/docs.

Objective:
Produce the complete build-planning package for WhoaThere: a decision-complete set of architecture, interface, policy, detection, operations, and roadmap artifacts that can be used to generate granular implementation plans for a deployable WhoaThere CLI and Vault.

Important context:
- The current repo is dedicated to the WhoaThere supply-chain security product.
- This goal is still planning work, not product implementation.
- Target macOS and Linux endpoints in parallel.
- Support npm and pip first: npm install, npm ci, npx/npm exec, pip install, pip3, and python -m pip.
- Compare AWS, Cloudflare, and hybrid Vault deployment paths.
- Bias AWS for hardened VPC/private-network detonation unless the comparison proves otherwise.
- Use fail-closed semantics for CI, high-risk installs, unsupported dependency source types, and scanner/proxy outages unless explicit break-glass policy applies.
- Treat Windows as a later expansion track.
- Do not make TLS MITM, LD_PRELOAD, DYLD_*, package-manager forks, or WASM the primary enforcement model.
- Full runtime application protection is out of MVP scope; import-time detonation is in scope.
- Phase 1 macOS endpoint semantics are beta containment, not GA containment.
- Phase 3 may promote cold-miss artifacts only after the artifact class satisfies a minimum allow-verdict contract.
- Cloudflare hybrid may serve stale approved artifacts only under a signed, digest-bound stale-serving contract.

Execution instructions:
1. Read /Users/jdc/src/whoathere/docs/README.md first.
2. Read /Users/jdc/src/whoathere/docs/interfaces-and-contracts.md, /Users/jdc/src/whoathere/docs/acceptance-test-matrix.md, and /Users/jdc/src/whoathere/docs/goal-pack-completion-checklist.md.
3. Execute GOAL-01 first.
4. Execute GOAL-02, GOAL-03, and GOAL-04 after GOAL-01 has enough outputs.
5. Execute GOAL-05, GOAL-06, and GOAL-08 after GOAL-02 through GOAL-04 have draft decisions.
6. Execute GOAL-07 last, using all prior outputs to produce the four downstream phase goals.
7. Execute GOAL-09 after review or after GOAL-07 if review findings are already known. GOAL-09 must harden release gates, test ownership, interface contracts, endpoint egress, macOS beta containment, Vault promotion, outage/break-glass, Cloudflare stale serving, and operations launch readiness.
8. Execute GOAL-10 when quality-hardening is requested. GOAL-10 must run three passes of rubric, evaluation, improvement plan, execution, and verification, unless a pass exits early with a clear evidence-backed reason.
9. Use subagents liberally for endpoint isolation, macOS security, Linux sandboxing, npm compatibility, Python packaging, AWS architecture, Cloudflare architecture, threat modeling, operations, and review.
10. For each goal pack, create an output directory under /Users/jdc/src/whoathere/docs/outputs/GOAL-XX/.
11. For each goal pack, produce every required deliverable listed in that goal pack or explicitly document an approved replacement.
12. For each goal pack, create /Users/jdc/src/whoathere/docs/outputs/GOAL-XX/completion-record.md using the template in goal-pack-completion-checklist.md.
13. Do not declare a goal complete until its required deliverables, acceptance criteria, exit gate, interface traceability, test traceability, and readiness tier are all satisfied.
14. At the end, create /Users/jdc/src/whoathere/docs/outputs/final-goal-pack-execution-summary.md with:
    - Completed goal list.
    - Produced artifact tree.
    - ADR index and statuses.
    - Interface ownership matrix.
    - Acceptance test ownership matrix.
    - Remediation/readiness matrix.
    - Remaining follow-up goals.
    - Whether the global done definition is satisfied.

Completion criteria:
- GOAL-01 through GOAL-08 each have a completion-record.md.
- All required deliverables are present or explicitly replaced.
- All ADRs have status, alternatives, tradeoffs, security impact, operational impact, compatibility impact, and revisit triggers.
- AWS, Cloudflare, and hybrid deployment ADRs identify authoritative ownership for secrets, keys, CAS, cache, metadata, verdicts, policy, audit, evidence, and deployment state.
- All interfaces in interfaces-and-contracts.md are specified, owned elsewhere, or explicitly not applicable.
- All tests in acceptance-test-matrix.md have an owning phase/subsystem and planned fixture or validation method.
- GOAL-07 produces the four downstream phase goals:
  - phase-1-mvp-local-cli-goal.md
  - phase-2-advanced-isolation-goal.md
  - phase-3-enterprise-vault-goal.md
  - phase-4-advanced-detonation-goal.md
- GOAL-09, when run, produces the remediation pack and upgrades completion language from artifact presence to planning readiness.
- GOAL-10, when run, produces three rubric/evaluation/improvement/verification passes and a quality verification manifest.
- The final package can be handed to another engineer or agent to generate granular implementation plans without re-deciding product scope.
```
