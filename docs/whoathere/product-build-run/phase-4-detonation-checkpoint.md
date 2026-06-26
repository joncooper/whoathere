# WhoaThere Phase 4 Detonation Checkpoint

## Scope

Phase 4 adds the first implementation slice for advanced detonation, behavior evidence, automation, and minimum admin workflow contracts. It does not run arbitrary public package code and does not claim production malware detonation.

The Phase 4 priority order is:

1. Typed behavior-evidence and admission-binding contracts.
2. Fixture-safe dynamic behavior coverage for npm and PyPI threat shapes.
3. Audit-safe admin/manual-review primitives before dashboard or production worker polish.

## Phase 4 MVP Standard Used

The initial Phase 4 standard was directionally correct, but it needed one clarification: production detonation workers are not required for this MVP slice. The standard used for verification was:

- Dynamic detonation exists as a real typed job/evidence pipeline, not only prose.
- Arbitrary package execution is disabled by default and cannot be enabled by the local fixture path.
- Fixture-safe behavior analysis runs only deterministic inert mock-canary fixtures under explicit local-dev/test mode.
- Behavior evidence captures lifecycle/build/import trigger type, process intent, filesystem write intent, environment access, credential-canary access, network and DNS attempts, delayed activation hints, native-extension risk, platform-specific risk, direct/git/tarball source risk, runner identity, isolation proof identity, egress proof identity, and configured Vault host.
- Evidence output is sanitized: no raw secrets, raw auth material, raw package bytes, raw environment dumps, raw network payloads, raw logs, raw nonces, or local private paths are emitted through API/audit summaries.
- Dynamic behavior results cannot contribute to admission unless they bind to the exact tenant, admission request, artifact, digest-derived cache key, evidence profile, job id, job kind, runner identity, runner session, isolation proof, egress proof, configured Vault host, freshness window, and audit event.
- Missing, failed, incomplete, stale, mismatched, overpermissive, raw-material-capturing, network-attempting, or untrusted dynamic evidence fails closed.
- npm postinstall exfiltration, PyPI PEP 517 build backend abuse, Python import-time payloads, DNS tunneling, HTTPS exfiltration, delayed CI activation, native extension abuse, platform-specific payloads, and direct/git/tarball dependency scenarios are represented by deterministic mock-canary fixtures.
- Admin/manual-review primitives exist as typed contracts for manual review, quarantine, deny, allow-after-review, break-glass, audit search, and audit export, with audit-safe output.
- Documentation must clearly distinguish implemented fixture-safe behavior analysis from deferred production detonation workers.

## Implemented Phase 4 Support

Phase 4 now provides:

- `whoathere-vault-api` dynamic behavior job planning and result binding.
- Dynamic behavior plan state and result state enums with reason-coded rejection.
- Dynamic behavior signal summary schema for process, filesystem, network, DNS, environment, credential, delayed-execution, native-extension, platform-specific, and direct-source signals.
- Strict result binding checks for same tenant, admission request, artifact, profile, job kind, cache key, runner id, runner session, isolation proof, egress proof, Vault host, freshness window, schema, log digest, and audit event.
- `whoathere-detonation` fixture-safe behavior harness that produces deterministic sanitized evidence without running arbitrary code.
- Mock-canary fixtures for clean npm lifecycle behavior, npm postinstall canary exfiltration, PyPI PEP 517 backend abuse, PyPI import-time abuse, DNS tunneling, HTTPS exfiltration, delayed CI activation, native extension abuse, platform-specific payloads, and direct/git/tarball dependency risk.
- Local-dev Vault simulation route: `POST /v1/dynamic-behavior-job-simulations`.
- Route-level tamper controls for wrong tenant/context/Vault/proof, stale results, overpermissive runner evidence, raw material capture, and fixture-mode mismatch.
- Admission-controller test coverage proving a bound clean dynamic behavior result can satisfy mandatory profile evidence, while rejected dynamic behavior evidence cannot promote an artifact.
- Typed admin workflow contracts for manual review, quarantine, deny, allow-after-review, break-glass, audit search, and audit export.

## Security Posture

Phase 4 still does not authorize endpoint package-manager install/build/import execution. Phase 1 and Phase 2 high-risk execution gates remain fail closed unless real same-subject containment and Vault-only egress proofs exist for the exact launch context.

Phase 4 also does not run arbitrary untrusted packages in Vault workers. The implemented dynamic path is a deterministic fixture-safe evidence contract used to validate schemas, reason codes, sanitization, and admission binding. Production dynamic detonation still requires isolated runner implementation, Vault-only egress enforcement, durable logs, worker authentication, capacity management, and incident workflows.

Vault registry serving remains Phase 3 promoted-cache-only. Dynamic evidence can contribute to promotion only after it is bound and admission-ready; rejected dynamic results are not usable as allow evidence.

## Exit Criteria Evidence

| Exit criterion | Evidence |
| --- | --- |
| typed dynamic job/evidence pipeline exists | `DynamicBehaviorJobRequest`, `DynamicBehaviorJobPlan`, `DynamicBehaviorJobResultRecord`, `DynamicBehaviorResultBinding`, and dynamic binding tests in `whoathere-vault-api`. |
| arbitrary execution stays disabled | plans always carry `execution_enabled=false`, reject non-fixture mode, and fixture outputs set `arbitrary_execution_attempted=false`; tests cover attempts and mismatch. |
| deterministic safe fixtures represent required threat shapes | `whoathere-detonation` implements clean, npm exfil, PyPI PEP 517, import-time, DNS, HTTPS, delayed CI, native extension, platform-specific, and direct-source fixtures. |
| behavior evidence captures required signal families | `DynamicBehaviorSignalSummary` and fixture tests cover process, filesystem, network, DNS, environment, credential, delayed, native, platform, and direct-source fields. |
| API/audit output is sanitized | fixture route and harness tests assert no canary token, local path, raw material, raw log, or network payload leakage. |
| mismatched or stale dynamic evidence fails closed | Vault API and Vault dev route tests cover wrong tenant, context, Vault host, runner session, isolation proof, egress proof, stale result, raw material, network attempt, and overpermissive evidence. |
| dynamic evidence cannot bypass admission binding | `whoathere-admission` test proves bound clean dynamic evidence can promote only with complete profile evidence and verified fetch, while rejected dynamic evidence fails closed. |
| admin workflow primitives exist without broad UI work | `AdminWorkflowAction`, `AdminWorkflowRequest`, `AdminWorkflowDecision`, and tests cover typed decisions, break-glass requirements, and audit-safe output. |
| Phase 1/2 endpoint execution remains fail closed | Full workspace validation continues to exercise launch/protect proof gates. |
| Phase 3 registry serving remains promoted-cache-only | Full workspace validation continues to exercise promoted-cache registry compatibility and denial paths. |

## Deferred Production Detonation Work

- Real isolated Linux runner or microVM execution for npm/pip install/build/import paths.
- macOS VM workers for macOS-specific package behavior.
- Production Vault-only egress enforcement and packet/audit proof collection for detonators.
- Durable behavior-log storage, signing, retention, export, and deletion workflows.
- Authenticated worker registration, scheduling, retry, timeout, and capacity controls.
- Real package archive unpack/install/import execution in isolated workers.
- Release-diff, reputation, maintainer-takeover, and anomaly automation.
- Full admin dashboard and production review queue.
- Deeper red-team validation with non-destructive mock malware beyond deterministic contract fixtures.

## Phase 4 Closeout Validation

Focused checks:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-vault-api -p whoathere-detonation
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-vault-dev
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-admission
```

Final validation:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
rg -n "[^[:ascii:]]" README.md docs/whoathere/product-build-run scripts whoathere/README.md whoathere/Cargo.toml whoathere/Cargo.lock whoathere/crates whoathere/examples whoathere/tests whoathere/probe-images
```

Result: all required Rust validation passed on this tree. The ASCII scan produced no matches. Focused CLI smoke checks for `clean_npm_lifecycle` and `npm_postinstall_canary_exfil` exercised the local-dev dynamic behavior route; the clean fixture bound with execution disabled, and the npm postinstall canary fixture failed closed with sanitized reason codes.
