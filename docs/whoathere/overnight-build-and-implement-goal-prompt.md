# `/goal` Prompt: Overnight Build Planning, Quality Passes, And Implementation Kickoff

Use this prompt with `/goal` when you want Codex to run overnight: first generate detailed build plans, then quality-harden those plans with 3-5 improvement passes, then start executing the approved detailed build plans.

```text
Execute the WhoaThere overnight build-planning and implementation kickoff run.

Workspace:
/Users/jdc/src/whoathere

Objective:
Generate granular, implementation-ready build plans for WhoaThere from the completed goal-pack package, quality-harden those plans with 3-5 rubric/evaluation/improvement/verification passes, then start executing the detailed build plans. Do not stop after planning unless a hard gate blocks implementation. If blocked by a research_required or validation_pending gate, document the blocking gate, execute all unblocked prerequisite work, and leave a precise resume point.

Important context:
- Treat /Users/jdc/src/whoathere/docs/whoathere as authoritative product-planning input.
- Existing Swift timer app files are unrelated unless explicitly superseded by the new WhoaThere repo layout.
- Preserve GOAL-09 and GOAL-10 decisions. Do not re-decide product scope.
- macOS Phase 1 is beta containment, not GA containment.
- AWS-only is the MVP Vault architecture.
- Cloudflare-only is rejected for MVP; hybrid is optional later and non-authoritative.
- Phase 3 may promote cold-miss artifacts only after the artifact class satisfies the minimum allow-verdict evidence contract.
- Cloudflare stale serving is allowed only under the signed digest-bound stale-approved policy.
- Break-glass must not promote unknown or unscanned artifacts.
- CI/high-risk paths must fail closed on Vault, policy, scanner, detonator, source, or egress ambiguity.
- Do not make TLS MITM, LD_PRELOAD, DYLD_*, package-manager forks, or WASM the primary enforcement model.

Read first:
1. docs/whoathere/README.md
2. docs/whoathere/outputs/final-goal-pack-execution-summary.md
3. docs/whoathere/outputs/GOAL-09/remediation-execution-summary.md
4. docs/whoathere/outputs/GOAL-09/phase-gate-scorecard.md
5. docs/whoathere/outputs/GOAL-09/primary-owner-test-matrix.md
6. docs/whoathere/outputs/GOAL-09/interface-schema-contracts.md
7. docs/whoathere/outputs/GOAL-10/downstream-goal-execution-addendum.md
8. docs/whoathere/outputs/GOAL-10/quality-verification-manifest.md

Stage 1: Generate detailed build plans
Create outputs under:
docs/whoathere/build-plans/

Generate these artifacts:
1. docs/whoathere/build-plans/phase-1-mvp-local-cli-build-plan.md
2. docs/whoathere/build-plans/phase-2-advanced-isolation-build-plan.md
3. docs/whoathere/build-plans/phase-3-enterprise-vault-build-plan.md
4. docs/whoathere/build-plans/phase-4-advanced-detonation-build-plan.md
5. docs/whoathere/build-plans/cross-phase-dependency-and-gate-map.md
6. docs/whoathere/build-plans/implementation-backlog.md
7. docs/whoathere/build-plans/initial-repo-file-plan.md
8. docs/whoathere/build-plans/overnight-build-summary.md

Each phase build plan must include:
- Objective and non-goals.
- Required source artifacts consumed.
- Work breakdown by milestone.
- Concrete repo/file/module plan.
- Interface/schema artifacts to create.
- Test harness and fixture plan.
- Verification commands.
- Release gate evidence required.
- Security/privacy/operations notes.
- Research_required and validation_pending gates.
- First implementation tasks in dependency order.

Stage 2: Quality-harden the build plans
Run at least 3 and at most 5 improvement passes over docs/whoathere/build-plans/.

For each pass, create:
- docs/whoathere/build-plans/quality/pass-N-rubric.md
- docs/whoathere/build-plans/quality/pass-N-evaluation.md
- docs/whoathere/build-plans/quality/pass-N-improvement-plan.md
- docs/whoathere/build-plans/quality/pass-N-execution-notes.md
- docs/whoathere/build-plans/quality/pass-N-verification.md

Each pass must:
1. Write a rubric to evaluate the current build plans.
2. Evaluate the build plans using the rubric.
3. Identify concrete improvements or explain clearly why no improvement is desirable.
4. Write an improvement plan.
5. Execute the improvement plan.
6. Verify the improvement plan succeeded.
7. Rerun the verification and fix issues if verification fails.

Required pass focus:
- Pass 1: build-plan completeness and implementation readiness.
- Pass 2: security invariants, fail-closed behavior, and research/validation gate preservation.
- Pass 3: testability, verification commands, and handoff quality.
- Optional Pass 4: implementation risk reduction and dependency sequencing if material gaps remain.
- Optional Pass 5: final adversarial review if any security-sensitive ambiguity remains.

Create:
docs/whoathere/build-plans/quality/quality-summary.md

The quality summary must state why the run stopped at 3, 4, or 5 passes.

Stage 3: Decide what implementation can start
After the quality passes, inspect the build plans and gates.

Start implementation only for work that is unblocked by GOAL-09 research_required and validation_pending gates. Default start order:
1. Phase 1 local CLI/repo foundation.
2. Shared Rust workspace and crates.
3. CLI command skeleton and config parsing.
4. PATH shim scaffolding.
5. Local policy/audit data types.
6. Fixture/test harness scaffolding.
7. Linux sandbox interface skeleton.
8. macOS beta containment interface skeleton and explicit mode labeling.

Do not implement production Vault promotion, Cloudflare stale serving, or advanced allow-verdict automation until the required research contracts are answered in the generated build plans.

Stage 4: Execute the first detailed build plan
Begin executing the Phase 1 MVP Local CLI build plan unless its own quality gates block all implementation. Make real code and repo changes where appropriate.

Expected implementation outputs may include:
- Rust workspace bootstrap.
- Crate/module skeletons.
- CLI parser skeleton.
- Config schema/types.
- Endpoint event/audit types.
- Shim discovery/scaffolding.
- Test fixture directory structure.
- Initial unit tests for config/event/policy primitives.
- README or developer notes for running tests.

While implementing:
- Prefer Rust and repo patterns from the generated plans.
- Keep implementation changes scoped to WhoaThere product files.
- Do not refactor unrelated existing Swift timer app files unless the build plan explicitly replaces the project structure.
- Use apply_patch for file edits.
- Run available tests/checks after changes.
- If toolchain setup is missing, create the planned files and record exact setup blockers.

Stage 5: Final overnight report
Create:
docs/whoathere/build-plans/overnight-implementation-report.md

The report must include:
- Build plans generated.
- Quality passes run and scores before/after.
- Improvements made during quality passes.
- Implementation work started.
- Files created/changed.
- Tests/checks run and results.
- Blockers and research gates still open.
- Exact next /goal prompt to continue from the current state.

Completion criteria:
- Build plans exist for all four phases.
- 3-5 quality passes exist with rubric, evaluation, improvement plan, execution notes, and verification.
- Quality summary explains the number of passes.
- Unblocked implementation work has started, preferably Phase 1.
- Tests/checks were run where possible, or blockers are explicit.
- Final report exists and gives an exact resume prompt.

Use subagents liberally:
- Endpoint/Linux/macOS implementation planning.
- npm compatibility.
- Python packaging.
- Rust workspace architecture.
- AWS/Vault architecture.
- Detection/detonation.
- Security/adversarial review.
- Operations/reliability.

Stay with the work as long as useful progress is possible. Do not mark the goal complete merely because the planning stage is complete; completion requires the quality passes and implementation kickoff too.
```

