# WhoaThere Product Build Run: Morning Orchestration Report

## Current Status

| Area | Status |
| --- | --- |
| Build-plan improvement loops | Complete: 5 review/improve/validate passes documented |
| Local CLI MVP | Built: command classification, status/doctor, endpoint setup diagnostics, protected command output, execution-request PATH shims with env-provided workspace/Vault/policy/audit defaults, shim dry-run/materialization, endpoint interception smoke harness, source scans, launch-context planning, containment launch planning, typed proof-gated launch plans, and one-shot Vault HTTP simulation with validated synthetic headers |
| Config and policy loading | Built: dependency-free config/policy parsers, schema-version rejection, `vault.url`, `config check`, `policy check`, and `protect --policy` |
| Endpoint safety primitives | Built: fail-closed labels, typed containment/egress proof model, proof provider SPI, provider verification challenges, persistable replay guard snapshots, file-backed replay store with schema-backed stale-lock recovery, threaded concurrent issue/consume coverage, minimized replay-store audit summaries, separate-process CLI stress coverage, and typed Vault challenge-authority API plus stateful local-dev issue/consume routes with durable-safe challenge records, a local file-backed challenge-authority store, minimized challenge-authority audit summaries, and consume metadata binding for the future CI/high-risk trust boundary; replay-store endpoint/env defaults, Docker admission durable replay-store wiring, replay-guard-owned active-probe receipt admission, Docker active-probe replay-admission mode, JSON challenge probe manifests, Docker active-probe executor harness, local Linux active-probe image contract, non-root Docker active-probe execution with UID/GID map evidence, controlled Docker internal-network configured-Vault allowance probe, launch-to-provider challenge bridge, `launch provider-check` diagnostic, explicit provider challenge evaluation command, Linux active-probe receipt contract and fixture validator, fail-closed Linux/macOS provider skeletons with read-only capability probes, explicit local provider posture evidence, target-host readiness gating, Linux namespace/packet-filter tooling diagnostics, Linux/macOS containment readiness diagnostics, provider smoke harnesses, verifier prerequisite plan contracts, test-only fake provider harness, proof provenance/subject/freshness/context/session summaries, default-deny-attested Vault-only egress policy model, cleanup lease/manifest model |
| Policy | Built: outage behavior, unsupported source behavior, dependency-confusion source policy, and package-identity policy enforcement in `protect` |
| Audit | Built: redacted JSONL record writer, launch proof/cleanup summaries, minimized replay-store admission summaries, minimized challenge-authority issue/consume summaries, local-dev challenge-authority `audit_path` JSONL opt-in, optional `launch audit --audit-path`, optional `protect --audit-path` deny records, optional Docker replay-store admission `--audit-path`, and broader npm/pip/proxy/cloud-token display redaction |
| Detection | Built: evidence profiles, text/JSON provider diagnostics with Linux/macOS readiness reasons, provider posture objects, host/target applicability, scoped provider readiness checks, verifier plans, fail-closed provider readiness check mode, static npm/PyPI manifest scanner, metadata-only static manifest job producer, immutable sanitized in-memory job-log receipts, npm/pip source-file scanner, custom pip requirements/constraint argv scanning, and metadata-only scanner/detonator evidence-job binding contracts |
| Safe wrapper execution | Built: process exit enforcement, endpoint setup readiness/export plan, combined endpoint smoke for setup/shims/PATH interception, package-identity gate before source/launch planning, source scan gate before runner planning, deterministic SHA-256 launch/source fingerprints, challenge-subject same-session fresh context-bound proof-aware launch gate before runner execution, execution-request shims, env-driven protect defaults, launch/protect audit JSONL, cleanup manifest reporting/execution, guarded runtime cleanup execution, explicit absolute-path readonly version-probe execution plan, install execution still gated |
| Vault prototype | Built: tenant-aware in-memory admission, profile/artifact-bound evidence-plus-fetch-result-gated promotion, deterministic promotion manifest JSON, canonical lowercase SHA-256 content-addressed cache keys, SHA-256 verified inert quarantine-to-promoted cache lifecycle with exact artifact/key lookup, non-network fetch-job planning/result binding schemas, metadata-only scanner/detonator evidence-job planning/result binding schemas, static manifest job simulation route with process-lifetime immutable sanitized job-log storage, typed Vault challenge-authority request/scenario/decision API, split issue/consume request/decision API, in-memory challenge authority model with durable-safe stored records that omit raw nonces, local `ChallengeAuthorityFileStore` persistence with private temp-then-rename writes and stale-lock recovery, local-dev challenge-authority simulation route, stateful local-dev `/v1/challenge-authority/issue` and `/v1/challenge-authority/consume` routes with escaped request-controlled JSON, embedded minimized audit summaries, consume metadata binding, explicit temp-scoped `store_path` opt-in for file-backed route persistence, explicit temp-scoped `audit_path` JSONL opt-in, and `vault challenge-sim` CLI wrapper, URL-encoded registry rendering helpers, promoted-only local-dev registry metadata, package-manager-shaped npm/PyPI local-dev registry compatibility aliases, deterministic safe npm `.tgz` and PyPI wheel fixture archives, Host-aware loopback metadata for non-default dev server ports, hardened repeatable temp-dir npm/pip compatibility smoke harness, exact-match promoted cache-byte serving, package-byte `HEAD` support, single byte-range support, conditional ETag handling, immutable cache validator/security headers, sanitized per-request server summaries, binary-safe HTTP response bodies, loopback-only local-dev HTTP router, and bounded loopback-only dev server with accepted stream read stabilization |
| Production readiness | Not complete: OS sandbox, real package execution, cloud Vault, production persistence, dynamic detonation, and deployment remain gated |

## Priority Note

Keep the existing build plan and phase structure intact, but bias endpoint work toward macOS first and Linux second. Windows is not a current priority and should remain a later expansion track unless explicitly reintroduced.

Execute the remaining build phases sequentially. Finish Phase 1 and its validation/exit criteria before beginning Phase 2 implementation, then proceed to Phase 3, then Phase 4. Later-phase contracts can remain documented as context, but implementation work should not jump ahead unless explicitly requested.

## Orchestration Rationale

I used a risk-first build order:

1. Stabilize contracts shared by endpoint, detector, policy, and Vault.
2. Add executable, local-only MVP slices behind fail-closed defaults.
3. Validate each slice with tests before adding the next one.
4. Keep package-manager execution, public registry fetches, and dynamic detonation out of this run until isolation is real.
5. Document every review/improve/validate loop so the handoff is auditable.

This favors reliable software that controls risk over broad but unsafe functionality.

## Safety Boundaries

- No actual malware was run.
- No untrusted npm/pip install, npm lifecycle script, Python build backend, Python import-time payload, or Node fixture script was executed.
- Real package-manager compatibility smokes installed only generated safe local-dev fixtures into `/private/tmp`: npm used `--ignore-scripts --no-audit --no-fund` with a temp cache, and pip used `--no-deps --disable-pip-version-check` with a temp target/cache. No public registry or package index was fetched.
- No public registry or package index was fetched.
- No scanner/detonator worker was executed; evidence-job and static-manifest-job simulations only validate metadata and reject execution, network, detonation attempts, raw log capture, tampered log digests, same-job log rewrites, and unknown fixture selectors.
- No TLS MITM, preload hook, shell profile edit, PATH mutation, or package-manager fork was introduced.
- Default materialized shims are only `npm`, `npx`, `pip`, and `pip3`; `python` and `python3` require explicit `--include-python` opt-in because default Python interception would break normal tooling. Shim/env guidance now includes optional `WHOATHERE_REPLAY_STORE` for admission diagnostics, but protected install execution remains gated.
- Explicit shim materialization was tested only under `/private/tmp/whoathere-shims-smoke-codex` and `/private/tmp/whoathere-python-shim-smoke-codex`.
- `protect` now returns nonzero process exit codes for denies, can append redacted package-identity/source/launch deny audit records with `--audit-path`, and can gate package identity, source-file, and launch-plan findings before runner planning; install/build/import execution remains refused.
- Custom pip `-r/--requirement` and `-c/--constraint` files require `--workspace` for safe inspection; traversal, unreadable files, cycles, symlink escapes, identity policy violations, and source overrides fail closed.
- Sanitized npm/pip launch context is compatibility planning only. It is not treated as network egress enforcement.
- Launch planning materializes private runtime config and cleanup manifests only after challenge-subject, same-session, fresh, SHA-256 launch-context-bound high-risk proof gates pass. CLI `--containment-available` and `--egress-enforced` are operator assertions, not verified controls, and still block high-risk install planning.
- `launch cleanup` is report-only unless `--execute` is passed, and guarded cleanup refuses non-WhoaThere temp roots, parent-directory escapes, and paths outside the runtime root.
- Normal builds do not include test-only verified proof helpers; those are behind the non-default `whoathere-sandbox/test-support` feature for unit tests.
- Dev Vault HTTP is an in-process local-dev router/server, not a production server and not a package registry; registry simulations and compatibility aliases render promoted metadata only, fail closed for unknown/unpromoted artifacts, and serve only inert simulation bytes or generated safe fixture archives through exact promoted artifact/cache-key lookup. The bounded dev server accepts only loopback binds, has a maximum request count, and exits on idle timeout.
- `scripts/whoathere-provider-smoke.sh` verifies provider diagnostics stay fail-closed and read-only: no active verification, package execution, OS mutation, network mutation, or public network probing.
- `scripts/whoathere-provider-challenge-smoke.sh` verifies explicit provider challenge evaluation stays fail-closed and diagnostic-only until providers can satisfy same-subject containment and Vault-only egress proofs.
- `launch provider-check` is diagnostic-only: it evaluates the generated launch challenge against the current provider skeleton, appends provider-check status, and still does not execute package managers, materialize runtimes, or mutate OS/network state.
- JSON challenge `probe_destinations` are declarative executor input only. They do not authorize execution, mint proofs, run probes, or mutate OS/network state.
- `evidence linux-active-probe-docker --execute` starts an explicit, ephemeral Docker container from the local `whoathere/linux-active-probe:local` image as non-root user `65532:65532`, with `--network none`, no-new-privileges, dropped capabilities, and resource limits. It emits receipt evidence only, renders no raw Docker logs, does not pull images, does not run package managers, and still reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- Docker active-probe user namespace evidence now records current UID/GID, current UID/GID maps, nested user namespace attempt status, and nested maps if available. Local OrbStack currently reports identity maps and denies nested unshare under seccomp, so the receipt remains fail-closed on `linux_active_probe_user_namespace_not_isolated`.
- `evidence linux-active-probe-docker --docker-network <name>` refuses to attach unless Docker reports the named network as internal. The internal-Vault smoke creates a throwaway internal network and inert Vault fixture, proves the configured Vault can be reached, denies every non-Vault challenge destination by internal-network boundary, and still fails closed because user namespace evidence remains unsatisfied.
- `evidence linux-active-probe-docker --admit` issues a replay-guard-owned challenge, consumes the real Docker receipt through admission, and renders replay ownership separately from receipt content and Docker diagnostics. With `--replay-store <path>` or `WHOATHERE_REPLAY_STORE`, issue/consume state is durable in a local file-backed store that persists nonce digests rather than raw nonces and fails closed on unavailable or corrupt state. The env default is applied only in admission mode. It still does not mint proofs or authorize execution.
- The local probe image is built from the existing BuildKit base with `--pull=false`, a constrained build context, and a script that emits only controlled `probe.*` facts.
- Linux `provider_active_probe` diagnostics are a receipt contract only. Current read-only evidence deliberately reports the active receipt as unsatisfied; no namespace, seccomp, cgroup, packet-filter, or network probe mutation is performed.
- `evidence linux-active-probe-fixture` validates deterministic receipt fixtures only. Complete fixtures can return command success for contract validation, but the command always reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- `evidence linux-active-probe-admission` validates replay-guard ownership and single-use consumption for active-probe receipts. Accepted admission is still not proof minting and still reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- Provider challenge replay guard state now has a persistable snapshot/restore boundary and a local file-backed store that persists nonce digests, not raw nonces. The store preserves single-use consume state across process/store boundaries, rejects corrupt or ambiguous duplicate state, recovers schema-backed stale lock files, has threaded concurrent issue/consume coverage with separate store handles, and has a separate-process CLI stress smoke. It can be used by Docker active-probe admission with `--replay-store <path>` or `WHOATHERE_REPLAY_STORE`. With `--audit-path <path>` or `WHOATHERE_AUDIT_PATH`, Docker admission writes minimized replay-store audit summaries that omit raw nonces, store paths, raw Docker logs, and raw evidence. It is not yet production challenge authority and does not authorize execution.
- `whoathere vault challenge-sim` and `POST /v1/challenge-authority-simulations` model the future Vault-side challenge authority contract with Vault-owned time, one-time consume, replay/unknown/mutation/expiry rejection, no raw nonce return, and fail-closed CLI exit codes. This is still a local-dev simulation, not a production distributed authority, and it reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- Split challenge-authority issue/consume state now stores `ChallengeAuthorityRecord` snapshots instead of full challenge objects. Records include subject, context hash, configured Vault host, probe destinations, validity window, consumed status, and explicit `raw_nonce_stored=false`; nonce material is generated only for transient issue output and is not persisted in the authority record.
- Challenge-authority issue/consume responses now include minimized audit summary objects for local-dev contract testing. The audit summary records operation, authority, request id, tenant id, challenge id, status, accepted flag, time-source metadata, expiry, probe count, nonce presence, raw nonce flags, and reason codes; it does not record raw nonce material, probe destinations, raw evidence, or store paths. Unknown and cross-tenant consume attempts do not expose record metadata.
- `ChallengeAuthorityFileStore` persists only durable-safe challenge records to local files using private temp files, atomic rename, and a schema-backed lock file. It rejects corrupt state, duplicate challenge ids, and any persisted `raw_nonce_stored=true` marker without mutating the existing store. This is still a local file-backed contract, not production distributed Vault storage.
- Local-dev challenge-authority issue/consume routes can explicitly opt into `ChallengeAuthorityFileStore` with a temp-scoped `store_path` form value. Route responses report `store_mode`, `store_available`, stale-lock recovery, and store reason codes without echoing the filesystem path. Non-temp, relative, empty, or parent-dir paths fail closed before store mutation.
- Local-dev challenge-authority issue/consume routes can explicitly opt into audit JSONL writes with a temp-scoped `audit_path` form value. Route responses report audit configured/written/error status without echoing the filesystem path, and invalid audit paths fail closed before store or authority mutation.
- Challenge-authority consume requires submitted subject, context hash, and configured Vault host to match the same-tenant issued record. Metadata mismatches fail closed without consuming the challenge, while unknown and cross-tenant consume attempts still do not expose issued record metadata.
- `scripts/whoathere-compat-smoke.sh` is a local-dev integration harness only. It chooses loopback ports, creates temp directories, runs npm/pip with safe flags, verifies sanitized request logs, and does not alter product install-execution gates.
- `scripts/whoathere-endpoint-smoke.sh` is a local endpoint wiring harness only. It creates temp workspace/shim dirs, verifies setup diagnostics and PATH shadowing, and confirms `npm ci` plus `pip install fixture` are intercepted and denied before npm or pip execute.
- I did not read or use credentials from other local projects.

## Review/Improve/Validate Loops

The initial pass artifacts are in `docs/product-build-run/quality/`; newer behavior slices are tracked in the canonical `docs/product-build-run/slice-handoff-ledger.md`:

- `phase-1-mvp-checkpoint.md`
- `pass-1-plan-executability.md`
- `pass-2-security-invariants.md`
- `pass-3-mvp-usability.md`
- `pass-4-reliability-and-handoff.md`
- `pass-5-interception-ergonomics.md`
- `quality-loop-summary.md`
- `../slice-handoff-ledger.md`

## Built Software

### Rust Workspace

Expanded `whoathere/Cargo.toml` to include:

- `whoathere-core`
- `whoathere-cli`
- `whoathere-policy`
- `whoathere-audit`
- `whoathere-sandbox`
- `whoathere-cache`
- `whoathere-evidence`
- `whoathere-detector`
- `whoathere-hash`
- `whoathere-job-log`
- `whoathere-vault-api`
- `whoathere-admission`
- `whoathere-registry`
- `whoathere-runner`
- `whoathere-source`
- `whoathere-launch`
- `whoathere-vault-dev`

### CLI Commands Exercised

```sh
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- doctor
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- status
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- config check whoathere/examples/whoathere.config
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- policy check whoathere/examples/whoathere.policy
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- policy check-source @company/build-tools public --internal-prefix @company/
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- policy check-source @company/build-tools public --policy whoathere/examples/whoathere.policy
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- shim install --dry-run
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- shim install --dest /private/tmp/whoathere-shims-smoke-codex
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- endpoint setup --shim-dir /private/tmp/whoathere-shims-smoke-codex --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --replay-store /private/tmp/whoathere-replay-store-smoke.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect npm -- --version
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --policy whoathere/examples/whoathere.policy npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --policy whoathere/tests/fixtures/package-identity/whoathere.policy --workspace whoathere/tests/fixtures/package-identity npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --policy whoathere/tests/fixtures/package-identity/whoathere.policy --workspace whoathere/tests/fixtures/package-identity pip -- install -r requirements.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --policy whoathere/tests/fixtures/custom-requirements/whoathere.policy --workspace whoathere/tests/fixtures/custom-requirements pip -- install -r custom-requirements.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute pip -- install -r custom-requirements.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --workspace whoathere/tests/fixtures/custom-requirements --vault-origin http://127.0.0.1:4873 pip -- install --requirement=source-override.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- source scan-workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- source scan-workspace whoathere/tests/fixtures/source-overrides --vault-origin http://127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- source context npm --vault-origin http://127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- source context pip --vault-origin http://127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --workspace whoathere/tests/fixtures/source-overrides --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --workspace whoathere/tests/fixtures/source-overrides --vault-origin https://registry.npmjs.org npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch plan --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-launch-smoke-codex-019efcca npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch plan --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch plan --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch provider-check --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --audit-path /private/tmp/whoathere-protect-audit-smoke.jsonl --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- scan manifest npm-package-json whoathere/tests/fixtures/npm/postinstall-exfil/package.json
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- scan manifest pyproject whoathere/tests/fixtures/pypi/pep517-backend/pyproject.toml
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence profiles
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --json
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --json --require-ready
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --scope linux
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence challenge --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence challenge --json --scope current --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-fixture --json --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873 --profile complete
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-admission --json --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873 --profile complete
scripts/whoathere-build-linux-active-probe-image.sh
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-docker --json --execute --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-docker --json --execute --admit --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-docker --json --execute --admit --replay-store /private/tmp/whoathere-replay-store-smoke.txt --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
scripts/whoathere-linux-active-probe-internal-vault-smoke.sh
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault simulate
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault simulate --complete
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault challenge-sim
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault challenge-sim --replay
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/challenge-authority-simulations replay=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /healthz
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/admission-simulations complete=false
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/admission-simulations complete=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/admission-simulations 'complete=true&fetch_missing=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/admission-simulations 'complete=true&fetch_mismatch=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/admission-simulations 'complete=true&evidence_profile_mismatch=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/admission-simulations 'complete=true&evidence_duplicate=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/admission-simulations 'complete=true&evidence_subject_mismatch=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/cache-simulations promote=false
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/cache-simulations promote=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/fetch-job-simulations valid=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/fetch-job-simulations invalid_digest=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/fetch-job-simulations digest_mismatch=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/evidence-job-simulations valid=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/evidence-job-simulations job_mismatch=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/evidence-job-simulations 'network_attempted=true&detonation_attempted=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/evidence-job-simulations worker_failed=true
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/static-manifest-job-simulations manifest=clean_npm
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/static-manifest-job-simulations manifest=malicious_npm
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/static-manifest-job-simulations manifest=pyproject
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/static-manifest-job-simulations 'manifest=clean_npm&raw_log_captured=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/static-manifest-job-simulations 'manifest=clean_npm&tamper_log_digest=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http POST /v1/static-manifest-job-simulations manifest=unknown
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/npm/fixture
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET '/v1/registry-simulations/npm/fixture?promoted=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET '/v1/registry-simulations/pypi/fixture?promoted=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 --header 'Range: bytes=6-10'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /healthz --header 'Content-Length: 999'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 --header 'If-None-Match: "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f"'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 --header 'If-None-Match: "sha256:0000000000000000000000000000000000000000000000000000000000000000"'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http HEAD /v1/registry-simulations/npm/tarballs/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET '/v1/registry-simulations/npm/tarballs/fixture/1.0.0?cache_key_mismatch=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http HEAD /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-compat/npm/fixture
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-compat/npm/tarballs/fixture/1.0.0/fixture-1.0.0.tgz --header 'Range: bytes=0-1'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-compat/pypi/simple/fixture/
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http HEAD /v1/registry-compat/pypi/files/pypi/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-serve --bind 127.0.0.1:48731 --max-requests 1 --idle-timeout-ms 10000
# Package-manager smoke: run bounded dev-serve on a loopback port, then run npm install from a fresh /private/tmp project with --ignore-scripts --no-audit --no-fund and a temp npm cache.
# Package-manager smoke: run bounded dev-serve on a loopback port, then run python3 -m pip install with --no-deps --disable-pip-version-check, a temp target, and a temp pip cache.
curl -fsS -i -H 'Range: bytes=6-10' http://127.0.0.1:48733/v1/registry-simulations/npm/tarballs/fixture/1.0.0
curl -sS -i -H 'Range: bytes=99-100' http://127.0.0.1:48734/v1/registry-simulations/npm/tarballs/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-serve --bind 127.0.0.1:48735 --max-requests 1 --idle-timeout-ms 10000
curl -fsS -i -H 'Range: bytes=6-10' http://127.0.0.1:48735/v1/registry-simulations/npm/tarballs/fixture/1.0.0
scripts/whoathere-provider-challenge-smoke.sh
scripts/whoathere-vault-challenge-authority-smoke.sh
scripts/whoathere-build-linux-active-probe-image.sh
scripts/whoathere-linux-active-probe-admission-smoke.sh
scripts/whoathere-linux-active-probe-docker-smoke.sh
scripts/whoathere-linux-active-probe-docker-admission-smoke.sh
scripts/whoathere-linux-active-probe-internal-vault-smoke.sh
scripts/whoathere-linux-active-probe-fixture-smoke.sh
scripts/whoathere-provider-smoke.sh
scripts/whoathere-compat-smoke.sh
scripts/whoathere-endpoint-smoke.sh
scripts/whoathere-replay-store-stress-smoke.sh
```

## Validation So Far

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --workspace --all-targets -- -D warnings
```

Current test count: 367 unit tests plus doctests.

Latest Phase 2 closeout validation:

- Added `phase-2-isolation-checkpoint.md` to freeze the Phase 2 cutline: macOS first, Linux second, Windows deferred, provider readiness classified as diagnostic/partial/beta/verified, and high-risk npm/pip execution still fail-closed until real same-subject containment plus Vault-only egress proofs exist.
- Added `ProviderControlLevel` to local provider readiness and verification-plan output so text and JSON diagnostics explicitly distinguish `diagnostic_only`, `partial`, `beta`, and `verified` controls.
- Focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-sandbox readiness -- --nocapture` passed with 8 tests.
- Focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli evidence_providers -- --nocapture` passed with 6 tests.
- Focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-launch -- --nocapture` passed with 17 tests.
- Focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-sandbox active_probe -- --nocapture` passed with 5 tests.
- Focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli protect -- --nocapture` passed with 30 tests.
- Focused `cargo test --manifest-path whoathere/Cargo.toml operator -- --nocapture` passed with 2 matching tests across CLI and sandbox crates.
- Final full `cargo test --manifest-path whoathere/Cargo.toml` passed with 367 unit tests plus doctests.
- Final `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.
- Final `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` passed.
- Final narrowed ASCII scan passed.

Latest Phase 1 closeout validation:

- Added `phase-1-mvp-checkpoint.md` to make the Phase 1 cutline explicit: macOS first, Linux second, Windows deferred, npm/pip shims and gates in scope, high-risk package-manager execution fail-closed, and Phase 2+ work deferred.
- Added `protect_pip_install_remains_fail_closed_after_source_gate` so pip clean-workspace high-risk install attempts have direct unit coverage matching the existing npm clean-workspace gate.
- Focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli protect_pip_install_remains_fail_closed_after_source_gate -- --nocapture` passed with 1 test.
- Focused `scripts/whoathere-endpoint-smoke.sh` passed, materializing four default shims and proving `npm ci` plus `pip install fixture` are intercepted and denied before package-manager execution.
- Focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-source -p whoathere-policy` passed with 35 unit tests plus doctests.
- Final full `cargo test --manifest-path whoathere/Cargo.toml` passed with 367 unit tests plus doctests.
- Final `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.
- Final `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` passed.
- Final narrowed ASCII scan passed.

Prior typed Vault challenge-authority consume-binding, route audit, route file-store, durable-record, and durable replay-store validation:

- Focused challenge-authority consume-binding tests passed for subject mismatch, context-hash mismatch, configured Vault-host mismatch, no consume-on-mismatch behavior, and successful consume after corrected metadata.
- Focused local-dev route tests passed for explicit `audit_path` JSONL writes, issue/consume audit records, minimized audit content, no audit/store path disclosure, no raw nonce leakage, and invalid audit path rejection before store mutation.
- Focused local-dev route tests passed for explicit file-backed issue/consume persistence across requests, replay rejection, store-path non-disclosure, and non-temp path rejection without file mutation.
- Focused file-backed challenge-authority tests passed for persisted single-use issue/consume state, replay rejection, raw nonce absence, corrupt-state fail-closed behavior without mutation, raw-nonce marker rejection, duplicate challenge-id rejection, and stale-lock recovery.
- Focused audit-schema tests passed for challenge-authority summaries without raw nonce or local path leakage.
- Focused route tests passed for challenge-authority issue/consume audit summaries, request-controlled JSON escaping, replay rejection, unknown challenge rejection, cross-tenant rejection, and no raw nonce leakage.
- Focused consume-decision API tests passed for same-tenant non-sensitive metadata and unknown/cross-tenant metadata withholding.
- Focused durable-record API tests passed for sanitized stored records, no raw nonce storage, first consume, consumed-state marking, replay rejection, unknown challenge rejection, tenant mismatch, expiry, and debug output without nonce material.
- Focused local-dev issue/consume route tests passed for stateful issue, consume, replay rejection, unknown challenge rejection, cross-tenant rejection, and no raw nonce leakage.
- Focused split issue/consume API tests passed for sanitized issue decisions, first consume, replay rejection, unknown challenge rejection, tenant mismatch, and expiry.
- Focused Vault API challenge-authority contract tests passed with accepted, replayed, unknown, tampered, and expired scenarios, and verified the decision debug surface does not expose raw nonces.
- Focused Vault challenge-authority route tests passed with accepted, replayed, unknown, tampered, and expired scenarios.
- Focused CLI `vault challenge-sim` tests passed, including fail-closed replay exit-code behavior.
- New `scripts/whoathere-vault-challenge-authority-smoke.sh` passed accepted, replay, unknown, tampered, and expired CLI cases.
- Focused file-store persistence/corruption tests passed.
- Focused duplicate record-field and duplicate challenge-ID tamper tests passed.
- Focused stale-lock recovery and threaded concurrent issue/consume tests passed.
- Focused minimized replay-store audit tests passed.
- Focused Docker admission replay-store tests passed.
- Focused endpoint setup replay-store default tests passed.
- Separate-process replay-store stress smoke passed with 12 CLI workers.
- Updated endpoint smoke passed with replay-store export assertions.
- Updated Docker admission smoke passed with no-network, `WHOATHERE_REPLAY_STORE` durable replay-store, replay, and internal-Vault paths.
- Full Rust tests, clippy, fmt check, targeted smoke scripts, script syntax, and ASCII scan passed for the latest slice.

Latest smoke outcomes:

| Command | Result |
| --- | --- |
| `policy check whoathere/examples/whoathere.policy` | passed, `policy_version=local-dev`, `namespace_rules=2` |
| `policy check-source @company/build-tools public --policy whoathere/examples/whoathere.policy` | passed, decision `Deny`, reason `dependency_confusion_public_source_denied` |
| `protect npm -- --version` | passed, classified `VersionProbe`, exit 0, no execution requested |
| `protect --policy whoathere/examples/whoathere.policy npm -- ci` | expected deny, process exit 20, no execution requested |
| `protect --execute --policy whoathere/tests/fixtures/package-identity/whoathere.policy --workspace whoathere/tests/fixtures/package-identity npm -- ci` | expected deny, `package_identity_status=blocked`, internal npm dependency denied before source scan or launch planning |
| `protect --execute --policy whoathere/tests/fixtures/package-identity/whoathere.policy --workspace whoathere/tests/fixtures/package-identity pip -- install -r requirements.txt` | expected deny, `package_identity_status=blocked`, internal Python requirement denied before source scan or launch planning |
| `protect --execute --policy whoathere/tests/fixtures/custom-requirements/whoathere.policy --workspace whoathere/tests/fixtures/custom-requirements pip -- install -r custom-requirements.txt` | expected deny, custom requirements file inspected under workspace and internal package denied at package-identity gate |
| `protect --execute pip -- install -r custom-requirements.txt` | expected deny, `requirements_argv_workspace_required`, launch planning not reached |
| `protect --execute --workspace whoathere/tests/fixtures/custom-requirements --vault-origin http://127.0.0.1:4873 pip -- install --requirement=source-override.txt` | expected deny, custom requirements file identity allowed but `requirements_index_override` blocked in source gate |
| `config check whoathere/examples/whoathere.config` | passed, `vault_url_set=true` |
| `source scan-workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873` | passed, `source_scan_status=ok`, 2 files scanned, 0 findings |
| `source scan-workspace whoathere/tests/fixtures/source-overrides --vault-origin http://127.0.0.1:4873` | expected deny, process exit 20, 4 blocking findings |
| `source context npm --vault-origin http://127.0.0.1:4873` | passed, planned env-clearing npm context, Vault registry only, execution disabled |
| `source context pip --vault-origin http://127.0.0.1:4873` | passed, planned env-clearing pip context, Vault index only, execution disabled |
| `shim install --dry-run --include-python` | passed, no mutation, renders default npm/npx/pip/pip3 shims plus optional python/python3 targets and `include_python=true` |
| `shim install --dest /private/tmp/whoathere-python-shim-smoke-codex --include-python` | passed, materialized 6 sandbox-dir shims including python and python3; no PATH mutation |
| `evidence challenge --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873` | expected deny, exit 20, selected current macOS provider, emitted valid challenge with 15 probes, and returned fail-closed unsatisfied attempt reasons without enabling verification or execution |
| `evidence challenge --json --scope current --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873` | expected deny, exit 20, JSON challenge contract rendered `challenge`, exact sorted `probe_destinations`, `challenge_attempt`, `containment`, and `egress` summaries |
| `evidence linux-active-probe-fixture --json --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873 --profile complete` | passed, validated a complete Linux active-probe receipt with `satisfied=true` while still reporting `authorization=false`, `proof_minted=false`, and `execution_allowed=false` |
| `evidence linux-active-probe-admission --json --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873 --profile complete` | passed, accepted a complete receipt only after replay-guard issue/consume while still reporting `authorization=false`, `proof_minted=false`, and `execution_allowed=false` |
| `scripts/whoathere-linux-active-probe-admission-smoke.sh` | passed, accepted an issued complete receipt for admission only, and rejected replayed, unknown-challenge, mutated-context, and incomplete receipts with fail-closed exit 20 |
| `scripts/whoathere-build-linux-active-probe-image.sh` | passed with escalation for Docker access, built `whoathere/linux-active-probe:local` from the local BuildKit base using `--pull=false` and a constrained Docker context |
| `evidence linux-active-probe-docker --json --execute --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873` | expected deny, exit 20, ran local Docker image `whoathere/linux-active-probe:local` as user `65532:65532` with no network, no-new-privileges, dropped capabilities, pids/memory/CPU limits, emitted `image_contract=whoathere-linux-active-probe.v1`, emitted UID/GID maps `0:0:4294967295`, nested userns attempt `denied`, emitted a complete `linux_active_probe.v1` receipt shape, proved no-new-privileges/seccomp/cgroup/no-network denial, and failed closed on user namespace plus Vault allowance gaps |
| `evidence linux-active-probe-docker --json --execute --admit --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873` | expected deny, exit 20, issued a replay-guard-owned challenge, ran the local Docker active probe, accepted replay consumption, rejected admission because the real Docker receipt remains unsatisfied, and still reported `authorization=false`, `proof_minted=false`, and `execution_allowed=false` |
| `scripts/whoathere-linux-active-probe-internal-vault-smoke.sh` | passed with escalation for Docker access, created a throwaway Docker internal network plus inert Vault fixture, verified `container_user=65532:65532`, `network_internal_verified=true`, configured Vault probe attempted and allowed, identity UID/GID maps recorded, nested userns denied under seccomp, exactly one allowed destination, fourteen denied non-Vault destinations, no missing probes, no non-Vault allows, and no trusted proof or execution authorization minted |
| `evidence linux-active-probe-docker --json --execute --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host whoathere-vault-fixture:4873 --docker-network bridge` | expected deny, exit 20, refused Docker's non-internal `bridge` network before container invocation with `docker_invoked=false`, `network_internal_verified=false`, and `linux_active_probe_docker_network_not_internal` |
| `scripts/whoathere-provider-challenge-smoke.sh` | passed, current-host explicit challenge JSON returned expected exit 20, `status=fail_closed`, `mutation=false`, `valid=true`, exact `probe_destinations`, `satisfied=false`, and provider challenge failure reasons |
| `scripts/whoathere-vault-challenge-authority-smoke.sh` | passed, accepted first consume with exit 0, rejected replay, unknown challenge, tampered context, and expired challenge with exit 20, and verified no raw nonce was returned |
| `scripts/whoathere-linux-active-probe-docker-smoke.sh` | passed with escalation for Docker access, built the local probe image, command exit 20, JSON parse ok, `image_contract_valid=true`, denied-probe count matched challenge probe count, and no trusted proof or execution authorization was minted |
| `scripts/whoathere-linux-active-probe-docker-admission-smoke.sh` | passed with escalation for Docker access, checked no-network real Docker output, `WHOATHERE_REPLAY_STORE` durable replay-store issue/consume, replay rejection, and internal-Vault real Docker output through replay-owned admission; all paths failed closed without proof minting or execution authorization |
| `scripts/whoathere-replay-store-stress-smoke.sh` | passed, built the CLI and ran 12 separate non-Docker `evidence linux-active-probe-docker --admit --replay-store ... --audit-path ...` processes against one shared replay-store file, verified every process failed closed without proof minting or execution, verified all store records were consumed and no lock remained, and verified per-worker audit records omitted raw nonces and local store/audit paths |
| `scripts/whoathere-linux-active-probe-fixture-smoke.sh` | passed, complete fixture exited 0, overpermissive and incomplete fixtures exited 20 with expected receipt failure reasons, and no proof was minted |
| `scripts/whoathere-provider-smoke.sh` | passed, current-host provider diagnostics returned expected exit 20, `status=fail_closed`, `provider_ready=false`, target-host readiness evidence, `proof_verification_enabled=false`, `can_verify_now=false`, and explicit no-active/no-package/no-OS-mutation/no-network-mutation/no-public-probe posture |
| `scripts/whoathere-endpoint-smoke.sh` | passed, chained fail-closed `endpoint setup`, materialized temp npm/npx/pip/pip3 shims, verified `npm` and `pip` resolve to temp shims, and confirmed expected-denied `npm ci` plus `pip install fixture` block at `launch_plan_status=blocked` before package-manager execution |
| `protect --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci` | expected deny, source scan passed, launch context planned, install execution still disabled/refused |
| `protect --workspace whoathere/tests/fixtures/source-overrides --vault-origin http://127.0.0.1:4873 npm -- ci` | expected deny, `execution_reason=source_scan_blocked`, runner plan not reached |
| `protect --workspace whoathere/tests/fixtures/source-overrides --vault-origin https://registry.npmjs.org npm -- ci` | expected deny, public registry rejected as invalid Vault origin before runner planning |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-launch-smoke-codex-019efcca npm -- ci` | expected deny, missing egress proof, runtime not materialized |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced npm -- ci` | expected deny, egress operator assertion not verified, runtime not materialized |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci` | expected deny, operator assertions are not verified proofs, SHA-256 launch/source hashes plus nonce/expiry-bound proof challenge rendered with 15 egress probes, install planning blocked |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-proof-smoke-codex-runtime npm -- ci` | expected deny, `egress_proof_missing`, `runtime_materialized=false`, directory absent |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-proof-smoke-codex-runtime-asserted --egress-enforced --containment-available npm -- ci` | expected deny, `OperatorAsserted` proof statuses, `egress_operator_assertion_not_verified`, directory absent |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-provider-smoke-runtime --egress-enforced --containment-available npm -- ci` | expected deny, unbound operator assertion subjects, `OperatorAssertion` mechanisms, `Unknown` egress scope, directory absent |
| `launch plan --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci` | expected deny, exit 20, emitted `proof_challenge_context_hash` and shell-safe `provider_challenge_command=whoathere evidence challenge --scope current ...`; `execution_allowed=false` |
| `launch provider-check --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci` | expected deny, exit 20, rendered normal blocked launch plan plus `launch_provider_check_status=fail_closed`, current-provider challenge attempt reasons, `runtime_materialized=false`, and `execution_allowed=false` |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-freshness-smoke-runtime --egress-enforced --containment-available npm -- ci` | expected deny, freshness fields rendered, `runtime_materialized=false`, directory absent |
| `launch plan --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-fingerprint-smoke-runtime --egress-enforced --containment-available npm -- ci` | expected deny, `launch_context_hash` and `source_scan_hash` rendered, directory absent |
| `launch audit --audit-path /private/tmp/whoathere-launch-audit-smoke.jsonl --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 --runtime-dir /private/tmp/whoathere-audit-smoke-runtime --egress-enforced --containment-available npm -- ci` | passed, wrote deny JSONL with proof/cleanup summaries, runtime directory absent |
| `protect --execute --workspace source-clean --vault-origin http://127.0.0.1:4873 npm -- ci` | expected deny, `execution_reason=launch_plan_blocked`, runner execution not reached |
| `protect --execute --audit-path /private/tmp/whoathere-protect-audit-smoke.jsonl --workspace source-clean --vault-origin http://127.0.0.1:4873 npm -- ci` | expected deny, `launch_audit_status=written`, wrote deny JSONL with proof/cleanup summaries |
| `vault dev-http GET /healthz` | passed, local-dev HTTP response 200 |
| `vault simulate --complete` | passed, `verdict=Allow`, `promoted=true`, canonical SHA-256 cache object key, and `fetch_job_id=fetch-sim-1` |
| `vault dev-http POST /v1/admission-simulations complete=false` | passed, local-dev HTTP response 409 fail-closed |
| `vault dev-http POST /v1/admission-simulations complete=true` | passed, local-dev HTTP response 200 with `generation_id=1`, SHA-256 verified `cache_object_key=blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f`, `fetch_job_id=fetch-dev-sim-1`, `fetch_quarantine_id=quarantine-1`, fetch byte metadata, `audit_event_id=audit-dev-sim-1`, and nested canonical `promotion_manifest` |
| `vault dev-http POST /v1/admission-simulations 'complete=true&fetch_missing=true'` | expected deny, local-dev HTTP response 409, reason `verified_fetch_result_missing`, `promoted=false` |
| `vault dev-http POST /v1/admission-simulations 'complete=true&fetch_mismatch=true'` | expected deny, local-dev HTTP response 409, reason `fetch_result_not_admission_ready`, reasons include `fetch_result_verified_digest_mismatch` and `fetch_result_cache_key_mismatch`, `promoted=false` |
| `vault dev-http POST /v1/admission-simulations 'complete=true&evidence_profile_mismatch=true'` | expected deny, local-dev HTTP response 409, reason `evidence_profile_id_mismatch`, `promoted=false` |
| `vault dev-http POST /v1/admission-simulations 'complete=true&evidence_duplicate=true'` | expected deny, local-dev HTTP response 409, reason `evidence_duplicate_job_result`, `promoted=false` |
| `vault dev-http POST /v1/admission-simulations 'complete=true&evidence_subject_mismatch=true'` | expected deny, local-dev HTTP response 409, reason `evidence_artifact_digest_mismatch`, `promoted=false` |
| `vault dev-http POST /v1/cache-simulations promote=false` | passed, local-dev HTTP response 200, quarantined inert bytes, `promoted=false` |
| `vault dev-http POST /v1/cache-simulations promote=true` | passed, local-dev HTTP response 200, promoted SHA-256 verified inert bytes to `blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f` |
| `vault dev-http POST /v1/fetch-job-simulations valid=true` | passed, local-dev HTTP response 200, state `Planned`, `fetch_enabled=false`, cache key `blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f`, reason `fetch_execution_not_enabled` |
| `vault dev-http POST /v1/fetch-job-simulations invalid_digest=true` | expected deny, local-dev HTTP response 409, state `Rejected`, empty cache object key, reason `artifact_digest_contains_unsafe_characters` |
| `vault dev-http POST /v1/fetch-job-simulations digest_mismatch=true` | expected deny, local-dev HTTP response 409, state `Rejected`, `fetch_enabled=false`, reason `fetch_expected_digest_mismatch` |
| `vault dev-http POST /v1/evidence-job-simulations valid=true` | passed, local-dev HTTP response 200, state `Bound`, `execution_enabled=false`, `detonation_attempted=false`, `network_attempted=false`, `evidence_binding_ready=true`, reason `evidence_job_execution_not_enabled` |
| `vault dev-http POST /v1/evidence-job-simulations job_mismatch=true` | expected deny, local-dev HTTP response 409, reason `evidence_job_result_job_mismatch` |
| `vault dev-http POST /v1/evidence-job-simulations 'network_attempted=true&detonation_attempted=true'` | expected deny, local-dev HTTP response 409, reasons include `evidence_job_result_network_attempted` and `evidence_job_result_detonation_attempted` |
| `vault dev-http POST /v1/evidence-job-simulations worker_failed=true` | expected deny, local-dev HTTP response 409, reason `evidence_job_result_not_passed` |
| `vault dev-http POST /v1/static-manifest-job-simulations 'manifest=clean_npm&job_id=smoke-static-log-clean'` | passed, local-dev HTTP response 200, static manifest job `Passed`, `evidence_binding_ready=true`, canonical `sha256:` log digest, `job_log_stored=true`, `job_log_id=logs/smoke-static-log-clean/<digest>`, sanitized byte length recorded, no execution/network/detonation/raw log capture |
| `vault dev-http POST /v1/static-manifest-job-simulations 'manifest=malicious_npm&job_id=smoke-static-log-malicious'` | expected deny, local-dev HTTP response 409, static manifest job `Failed`, sanitized job log still stored for audit, reasons include `npm_lifecycle_postinstall` and `evidence_job_result_not_passed`, no raw script command rendered |
| `vault dev-http POST /v1/static-manifest-job-simulations manifest=pyproject` | passed, local-dev HTTP response 200, PEP 517 metadata recorded as suspicious reason `pypi_pep517_build_backend`, sanitized job log stored, no execution/network/detonation |
| `vault dev-http POST /v1/static-manifest-job-simulations 'manifest=clean_npm&job_id=smoke-static-log-raw&raw_log_captured=true'` | expected deny, local-dev HTTP response 409, reason `job_log_raw_log_captured`, `job_log_stored=false` |
| `vault dev-http POST /v1/static-manifest-job-simulations 'manifest=clean_npm&job_id=smoke-static-log-tamper&tamper_log_digest=true'` | expected deny, local-dev HTTP response 409, reason `job_log_digest_mismatch`, `job_log_stored=false` |
| `vault dev-http POST /v1/static-manifest-job-simulations manifest=unknown` | expected deny, local-dev HTTP response 409, reason `static_manifest_selector_invalid` |
| `vault dev-http GET /v1/evidence-profiles` | passed, local-dev profile JSON with no registry serving |
| `vault dev-http GET /v1/registry-simulations/npm/fixture` | expected deny, local-dev HTTP response 503, reason `artifact_not_promoted`, no package bytes served |
| `vault dev-http GET '/v1/registry-simulations/npm/fixture?promoted=true'` | passed, local-dev HTTP response 200 with npm packument metadata, local tarball URL, SHA-256 integrity, and no public registry URL |
| `vault dev-http GET '/v1/registry-simulations/pypi/fixture?promoted=true'` | passed, local-dev HTTP response 200 with PyPI Simple HTML metadata, local href, SHA-256 fragment, and no public index URL |
| `vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0` | passed, local-dev HTTP response 200, `application/octet-stream`, 25 fixed inert promoted cache bytes, no registry fetch |
| `vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 --header 'Range: bytes=6-10'` | passed, socketless local-dev HTTP simulation response 206, `Content-Range: bytes 6-10/25`, body `cache` |
| `vault dev-http GET /healthz --header 'Content-Length: 999'` | expected deny, local-dev CLI response `status=fail_closed`, reason `dev_http_header_reserved`, request not routed |
| `vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 --header 'If-None-Match: "<current-etag>"'` | passed, socketless local-dev HTTP simulation response 304, `Content-Length: 0`, cache validators present, and no body bytes |
| `vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 --header 'If-None-Match: "<mismatched-etag>"'` | passed, socketless local-dev HTTP simulation response 200 with the promoted inert bytes |
| `vault dev-http HEAD /v1/registry-simulations/npm/tarballs/fixture/1.0.0` | passed, local-dev HTTP response 200, `Content-Length: 25`, immutable private cache control, SHA-256 ETag, `X-Content-Type-Options: nosniff`, and no body bytes |
| `vault dev-http GET '/v1/registry-simulations/npm/tarballs/fixture/1.0.0?cache_key_mismatch=true'` | expected deny, local-dev HTTP response 409, reason `cache_promoted_object_key_mismatch`, `served=false` |
| `vault dev-http GET /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0` | passed, local-dev HTTP response 200, `application/octet-stream`, 25 fixed inert promoted cache bytes, no public index fetch |
| `vault dev-http HEAD /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0` | passed, local-dev HTTP response 200, `Content-Length: 25`, immutable private cache control, SHA-256 ETag, `X-Content-Type-Options: nosniff`, and no body bytes |
| `vault dev-http GET /v1/registry-compat/npm/fixture` | passed, package-manager-shaped local-dev npm packument response 200 with `.tgz` tarball URL, SRI `sha256-...` integrity, explicit empty scripts object, and no public registry URL |
| `vault dev-http GET /v1/registry-compat/npm/tarballs/fixture/1.0.0/fixture-1.0.0.tgz --header 'Range: bytes=0-1'` | passed, package-manager-shaped local-dev npm tarball alias response 206, `Content-Range: bytes 0-1/3095`, immutable cache validators, and gzip magic bytes |
| `vault dev-http GET /v1/registry-compat/pypi/simple/fixture/` | passed, package-manager-shaped local-dev PyPI Simple response 200 with `.whl` file URL, standard `#sha256=` fragment, and no public index URL |
| `vault dev-http HEAD /v1/registry-compat/pypi/files/pypi/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl` | passed, package-manager-shaped local-dev PyPI file alias response 200, `Content-Length: 889`, immutable cache validators, and no body bytes |
| bounded `vault dev-serve --bind 127.0.0.1:4873 ...` plus temp-dir `npm install fixture@1.0.0 --registry http://127.0.0.1:4873/v1/registry-compat/npm --ignore-scripts --no-audit --no-fund` | passed with escalation for loopback binding, npm installed generated safe `fixture@1.0.0` from the local `.tgz`; server summary showed only sanitized npm metadata/tarball request logs |
| bounded `vault dev-serve --bind 127.0.0.1:4873 ...` plus temp-dir `python3 -m pip install --disable-pip-version-check --no-deps --index-url http://127.0.0.1:4873/v1/registry-compat/pypi/simple --target <temp-target> fixture==1.0.0` | passed with escalation for loopback binding, pip installed generated safe `fixture==1.0.0` wheel into a temp target; metadata files were inspected without importing the package |
| bounded `vault dev-serve --bind 127.0.0.1:48743 --max-requests 2 ...` plus temp-dir npm install against `http://127.0.0.1:48743/v1/registry-compat/npm` | passed with escalation for loopback binding, proving npm compat metadata uses the incoming loopback Host/port; server exited after 2 sanitized requests: npm metadata and npm tarball |
| bounded `vault dev-serve --bind 127.0.0.1:48742 --max-requests 2 ...` plus temp-dir pip install against `http://127.0.0.1:48742/v1/registry-compat/pypi/simple` | passed with escalation for loopback binding, proving PyPI compat metadata uses the incoming loopback Host/port; server exited after 2 sanitized requests: PyPI metadata and PyPI wheel |
| `scripts/whoathere-compat-smoke.sh` | passed with escalation for loopback binding, chose allocated loopback ports, ran npm and pip safe-fixture installs in temp directories, verified package metadata, and verified sanitized server summaries for npm metadata/tarball and PyPI metadata/wheel routes |
| `vault dev-serve --bind 127.0.0.1:48731 --max-requests 1 --idle-timeout-ms 10000` plus `curl http://127.0.0.1:48731/v1/registry-simulations/npm/tarballs/fixture/1.0.0` | passed with escalation for loopback binding, curl returned `inert cache fixture bytes`, server exited with `served_requests=1` |
| `vault dev-serve --bind 127.0.0.1:48732 --max-requests 1 --idle-timeout-ms 10000` plus `curl -fsSI http://127.0.0.1:48732/v1/registry-simulations/npm/tarballs/fixture/1.0.0` | passed with escalation for loopback binding, curl returned only headers with `Content-Length: 25`, immutable cache control, SHA-256 ETag, `nosniff`, and the server exited with `served_requests=1` |
| `vault dev-serve --bind 127.0.0.1:48733 --max-requests 1 --idle-timeout-ms 10000` plus `curl -fsS -i -H 'Range: bytes=6-10' http://127.0.0.1:48733/v1/registry-simulations/npm/tarballs/fixture/1.0.0` | passed with escalation for loopback binding, local-dev HTTP response 206, `Content-Range: bytes 6-10/25`, `Accept-Ranges: bytes`, body `cache`, and server exit with `served_requests=1` |
| `vault dev-serve --bind 127.0.0.1:48734 --max-requests 1 --idle-timeout-ms 10000` plus `curl -sS -i -H 'Range: bytes=99-100' http://127.0.0.1:48734/v1/registry-simulations/npm/tarballs/fixture/1.0.0` | expected deny, local-dev HTTP response 416, `Content-Range: bytes */25`, reason `range_not_satisfiable`, `served=false`, and server exit with `served_requests=1` |
| `vault dev-serve --bind 127.0.0.1:48735 --max-requests 1 --idle-timeout-ms 10000` plus `curl -fsS -i -H 'Range: bytes=6-10' ...` with a synthetic sensitive header | passed with escalation for loopback binding, local-dev HTTP response 206, server summary emitted one sanitized request log with route/status/range/byte counts, `request_body_logged=false`, `response_body_logged=false`, and no sensitive header or response body content |
| `evidence providers` | passed, renders fail-closed Linux/macOS provider diagnostics plus challenge-first provider attempts, local provider posture, missing-probe/non-fresh reason codes, Linux/macOS readiness reasons, and `proof_verification_enabled=false` |
| `evidence providers --json` | passed, renders schema-versioned fail-closed provider diagnostics, challenge-first provider attempts with 15-probe challenges, exact `probe_destinations`, challenge expiry/nonce-presence fields, posture objects with host/target/applicability/no-mutation flags, verifier plans with `can_verify_now=false`, and redacted evidence arrays |
| `evidence providers --json --require-ready` | expected deny, process exit 20, status `fail_closed`, `provider_ready=false`, `can_verify_now=false`, and provider posture confirms no active verification, package execution, OS mutation, network mutation, or public network probe attempt |
| `evidence providers --json --require-ready --scope current` | expected deny, process exit 20, filters readiness to the current host provider, keeps `provider_ready=false`, and preserves fail-closed posture |
| `evidence providers --scope linux` | passed, filters text diagnostics to Linux provider evidence while reporting current host platform separately; renders `provider_active_probe provider=linux`, active receipt `satisfied=false`, missing/invalid active receipt reasons, no allowed probes, and no package execution or public probe attempt |
| `evidence providers --json --scope windows` | expected misuse, process exit 64, reason `invalid_provider_scope` |

Additional checks:

- Narrowed ASCII scan over `README.md`, `docs/product-build-run`, `whoathere`, and `scripts` passed with no non-ASCII matches. The broad `docs` tree includes pre-existing exported HTML transcripts with non-ASCII prose and is intentionally not used as the edited-source ASCII gate.
- `docker ps --format ...` after the Docker active-probe smoke showed no leftover active-probe containers; only the pre-existing BuildKit builder container remained.
- `docker image ls --format ...` confirmed `whoathere/linux-active-probe:local` and `moby/buildkit:buildx-stable-1` were present locally.
- Safety-sensitive code-path scan found product code still refuses protected npm/pip install execution and does not invoke Python build backends, Node lifecycle scripts, imports, public registry fetches, or detonation. Documentation now includes explicit local safe-fixture npm/pip compatibility smoke commands.
- `git status --short` failed because `/Users/jdc/src/whoathere` is not a Git repository from the shell's perspective.

## Not Done Yet

- Real package-manager install/build/import execution wrapper.
- Trusted OS containment proof provider evidence collector and verifier that can emit same-subject `Verified` launch proofs.
- Independent Vault-only egress enforcement provider evidence collector and verifier that can emit same-subject `Verified` launch proofs; registry/index steering and CLI assertions are not sufficient.
- Trusted Docker/OrbStack-backed Linux active-probe verifier that can satisfy user namespace isolation plus default-deny-except-configured-Vault, use a production Vault-backed challenge authority with durable replay prevention and audit policy, verify probe image provenance, and map receipts into trusted proofs.
- Ambient environment policy beyond launch-context scrub planning.
- Linux namespace/seccomp/cgroup/Landlock runner.
- macOS VM helper.
- Signed policy distribution.
- Real npm/PyPI registry compatibility server with durable, authenticated real package-byte serving.
- AWS/Cloudflare deployment artifacts.
- Dynamic detonation workers.
- Durable append-only job-log storage, worker signatures, retention, and production audit storage/auth/admin control plane.

## Next Best Work

1. Close the remaining Docker active-probe proof gaps: a runtime-satisfied remapped current-process user namespace, production Vault-backed challenge authority, production audit retention/tamper-evidence policy, production image provenance/signing policy, and explicit verifier mapping into trusted containment/egress proofs.
2. Bind source-scan hashes into provider evidence or audit policy where needed.
3. Convert the fake-provider harness into provider-contract integration tests for real Linux/macOS collectors as they land.
4. Replace in-memory job-log storage with durable append-only storage tied to worker identity, tenant authz, retention, and production audit policy.
5. Decide high-risk CI behavior for audit-sink write failures and production audit storage/auth.

## Latest Continuation Notes

The current Phase 1 closeout checkpoint freezes the secure local CLI MVP cutline:

- Phase 1 is documented in `docs/product-build-run/phase-1-mvp-checkpoint.md`.
- Endpoint priority is macOS first, Linux second, Windows deferred.
- PATH shims for `npm`, `npx`, `pip`, and `pip3` remain the default interception mechanism; `python`/`python3` stay explicit opt-in.
- `protect` gates npm/pip source, policy, package identity, launch, and audit paths before package-manager execution.
- High-risk npm/pip install execution remains fail closed until Phase 2 proves real containment and Vault-only egress.
- Full validation passed with 367 unit tests plus doctests, clippy, fmt check, endpoint smoke, source/policy focused tests, and ASCII scan.

The prior Vault challenge-authority consume-binding slice closes the challenge-id-only consume gap:

- `ChallengeConsumeRequest` now includes submitted subject, context hash, and configured Vault host.
- In-memory and file-backed challenge-authority consume paths compare submitted metadata against the same-tenant issued record.
- Subject/context/Vault-host mismatches fail closed with explicit reason codes and do not mark the challenge consumed.
- Unknown and cross-tenant consume attempts still avoid exposing issued record metadata.
- Local-dev `/v1/challenge-authority/consume` accepts `subject`, `context_hash`, and `vault_host` form fields and routes them through the same binding checks.
- Full validation passed with 366 unit tests plus doctests, clippy, fmt check, the Vault challenge-authority smoke, targeted script syntax checks, and ASCII scan.

The current Vault challenge-authority route audit-path slice makes minimized audit writes exercisable through local-dev HTTP:

- `/v1/challenge-authority/issue` and `/v1/challenge-authority/consume` accept explicit `audit_path=<absolute-temp-path>`.
- Audit-enabled route responses include `audit_configured`, `audit_status`, and `audit_reason_codes`.
- Audit JSONL records use the shared `AuditRecord` and `AuditChallengeAuthoritySummary` schemas.
- Audit paths and store paths are not echoed in route responses or audit records.
- Invalid audit paths fail closed before issue/consume store mutation.
- Full validation passed with 363 unit tests plus doctests, clippy, fmt check, the Vault challenge-authority smoke, targeted script syntax checks, and ASCII scan.

The prior Vault challenge-authority route file-store opt-in slice makes the durable store exercisable through local-dev HTTP:

- `/v1/challenge-authority/issue` and `/v1/challenge-authority/consume` accept explicit `store_path=<absolute-temp-path>`.
- File-backed route responses include `store_mode=file`, store availability, stale-lock recovery, and store reason codes.
- Store paths are not echoed in responses.
- Non-temp, relative, empty, or parent-dir store paths fail closed before mutation.
- Full validation passed with 361 unit tests plus doctests, clippy, fmt check, the Vault challenge-authority smoke, targeted script syntax checks, and ASCII scan.

The prior Vault challenge-authority file-store slice adds a local durable-store contract for sanitized challenge records:

- Added `ChallengeAuthorityFileStore` to `whoathere-vault-api`.
- The store persists `ChallengeAuthorityRecord` values, not full challenge objects or raw nonces.
- Writes use private temp files and rename into place; lock files recover from schema-backed stale locks.
- Corrupt stores, duplicate challenge ids, and persisted `raw_nonce_stored=true` all fail closed without mutating the store.
- Full validation passed with 359 unit tests plus doctests, clippy, fmt check, the Vault challenge-authority smoke, targeted script syntax checks, and ASCII scan.

The prior Vault challenge-authority audit summary and JSON escaping slice makes issue/consume routes closer to production audit behavior:

- Added `AuditChallengeAuthoritySummary` to the shared audit crate and `AuditRecord` JSONL output.
- Local-dev `/v1/challenge-authority/issue` and `/v1/challenge-authority/consume` responses now include `audit_event_id` and `challenge_authority_audit_summary`.
- Consume decisions now carry same-tenant non-sensitive metadata needed for audit summaries, while unknown and cross-tenant attempts withhold record metadata.
- Challenge-authority route JSON now escapes request-controlled fields before rendering.
- Full validation passed with 355 unit tests plus doctests, clippy, fmt check, the Vault challenge-authority smoke, targeted script syntax checks, and ASCII scan.

The prior Vault challenge-authority durable-safe record slice removes full challenge objects from authority state:

- Added `ChallengeAuthorityRecord` as the process/durable-store-shaped state object for issued challenges.
- `InMemoryChallengeAuthority` now stores sanitized records keyed by challenge id instead of storing raw `ProviderVerificationChallenge` values.
- Issue still returns a transient challenge id/nonce-backed decision, but stored state records `nonce_present=true` and `raw_nonce_stored=false`.
- Consume looks up records by challenge id, enforces tenant ownership, rejects replay/unknown/expired challenges, and marks accepted records as consumed.
- Full validation passed with 353 unit tests plus doctests, clippy, fmt check, the Vault challenge-authority smoke, targeted script syntax checks, and ASCII scan; focused API tests passed for stored-record sanitization and replay/tenant/expiry behavior.

The prior Vault challenge-authority local-dev issue/consume route slice exposes the split contract through service-shaped routes:

- Added `POST /v1/challenge-authority/issue`.
- Added `POST /v1/challenge-authority/consume`.
- Added process-local `InMemoryChallengeAuthority` state in the Vault dev router.
- Route tests prove issue/consume/replay, unknown challenge, cross-tenant rejection, and no raw nonce leakage.
- Full validation passed with 353 unit tests plus doctests, clippy, fmt, the Vault challenge-authority smoke, targeted script syntax checks, and ASCII scan.

The prior Vault challenge-authority split issue/consume slice moved the contract closer to a real service boundary:

- Added `ChallengeIssueRequest`, `ChallengeIssueDecision`, `ChallengeConsumeRequest`, and `ChallengeConsumeDecision`.
- Added `InMemoryChallengeAuthority` with private raw challenge storage, sanitized issue results, tenant-bound consume, replay rejection, unknown challenge rejection, and expiry rejection.
- Confirmed issue/consume decision debug output does not expose `proof-nonce-`.

The prior Vault challenge-authority API contract slice moved the simulation behavior behind typed Vault API objects:

- Added `ChallengeAuthorityRequest`, `ChallengeAuthorityScenario`, `ChallengeAuthorityDecision`, and `ChallengeAuthorityStatus` to `whoathere-vault-api`.
- Added `plan_challenge_authority(...)` with shared sandbox replay-guard semantics for first consume, replay, unknown challenge, context mutation, and expiry.
- Added API tests proving the typed decision surface does not expose raw challenge nonces.
- Refactored the local-dev Vault route to call the typed API contract and render `ChallengeAuthorityDecision`.
- Removed the direct sandbox dependency from `whoathere-vault-dev`; the behavior dependency is now owned by `whoathere-vault-api`.

The prior Vault challenge-authority simulation slice established the local-dev route and CLI wrapper:

- Added `POST /v1/challenge-authority-simulations` in the local-dev Vault router.
- Added `whoathere vault challenge-sim [--replay|--unknown-challenge|--mutate-context|--expired]`.
- The simulation issues from a Vault-owned clock, consumes once, rejects replay/unknown/mutated/expired submissions, and never returns raw challenge nonces.
- The route and CLI explicitly report `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- The first smoke found fail-closed JSON could still exit 0 through the CLI wrapper; the wrapper now emits a top-level `exit_code=` line and fail-closed scenarios exit 20.
- Added focused Vault dev and CLI tests plus `scripts/whoathere-vault-challenge-authority-smoke.sh`.

The prior replay-store audit/separate-process stress slice made replay-store admission more observable and better exercised across process boundaries:

- Added `AuditReplayStoreSummary` to the audit JSONL model.
- `whoathere evidence linux-active-probe-docker --admit` now accepts `--audit-path <path>` and honors `WHOATHERE_AUDIT_PATH`.
- Docker replay-store admission audit records include configured/operation/available/stale-lock-recovered/challenge-id/replay-status/accepted/reason-code fields.
- Audit records intentionally omit replay-store paths, audit paths, raw challenge nonces, raw Docker logs, and raw evidence payloads.
- Replay-store issue/consume now have outcome-aware variants so audit can record stale-lock recovery without changing existing issue/consume callers.
- Added issue-failure audit coverage for corrupt replay-store state.
- Added `scripts/whoathere-replay-store-stress-smoke.sh`, which builds the CLI and runs 12 separate non-Docker admission processes against one shared replay-store file with per-worker audit files.
- The stress smoke verifies all processes fail closed without proof minting or execution, every replay-store record is consumed, no sidecar lock remains, and every audit record is minimized.
- Current validation: focused audit replay-store test passed with 1 test; focused sandbox file-store tests passed with 4 tests; focused Docker active-probe CLI tests passed with 8 tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 342 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; replay-store stress, endpoint, provider, compatibility, fixture, admission, Docker active-probe, Docker replay-admission, and internal-Vault smokes passed.
- Remaining production work: source challenge time from a trusted clock, decide local file versus Vault-backed challenge authority for CI, define production audit retention/tamper-evidence/admin policy, and decide whether many writers to one production audit sink need locked append or queue-backed writes.

Previous replay-store stale-lock/concurrency hardening slice reduced local replay-store operational risk:

- Added schema-backed replay-store lock files with `created_at_unix_seconds` and process id metadata.
- Store `issue`, `consume`, `prune_expired`, and `snapshots` now share the same lock acquisition path.
- Schema-valid stale locks are recovered after the replay-store TTL; malformed or legacy lock files fall back to filesystem mtime age.
- Fresh lock contention still fails closed with `WouldBlock` instead of falling back to unsafe in-memory state.
- Added a focused stale-lock recovery test.
- Added a threaded concurrency test with eight independent store handles issuing and consuming challenges against the same store file, then verifying all persisted snapshots are consumed and the sidecar lock is gone.
- Current validation: focused sandbox file-store tests passed with 4 tests; focused Docker active-probe tests passed with 6 tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 340 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; endpoint, provider, compatibility, fixture, admission, Docker active-probe, Docker replay-admission, and internal-Vault smokes passed.
- Remaining production work: source challenge time from a trusted clock and decide whether CI should use local file-backed or Vault-backed challenge authority.

Previous replay-store endpoint/defaults slice made the durable store usable from normal setup guidance:

- Added optional `--replay-store <path>` to `endpoint setup`.
- Added `WHOATHERE_REPLAY_STORE` to shim/env-default guidance.
- Endpoint setup now renders `replay_store=...` and `export_WHOATHERE_REPLAY_STORE=...` when configured.
- Docker active-probe admission now uses `WHOATHERE_REPLAY_STORE` as the durable replay-store path only when `--admit` is active and no explicit `--replay-store` is supplied.
- Non-admission Docker diagnostics ignore the env default, avoiding accidental misuse errors when the endpoint environment is configured.
- Updated endpoint smoke to assert replay-store export output and run shim-style denied npm/pip flows with the env var present.
- Updated Docker replay-admission smoke so the stored no-network path uses `WHOATHERE_REPLAY_STORE`, while still checking digest-backed consumed state and no raw nonce persistence.
- Validation at that slice: focused endpoint setup tests passed with 3 tests; focused Docker active-probe tests passed with 6 tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 338 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; endpoint smoke and updated Docker replay-admission smoke passed.
- Remaining production work: define production path policy, add trusted-clock behavior, define production audit sink behavior, and decide whether local replay state should be used in CI.

Previous Docker admission durable replay-store wiring slice turned the local file store into an explicit Docker admission option:

- Added `--replay-store <path>` to `whoathere evidence linux-active-probe-docker --admit`.
- Added `admit_linux_active_probe_receipt_with_replay_decision` so durable file-store consume decisions can feed the same admission object as the in-memory replay guard.
- Added JSON/text replay-store status output with configured/path/operation/availability/reason-code fields.
- Store failures now fail closed with exit 20 and replay-store reason codes; corrupt state is not overwritten, and commands do not fall back to in-memory approval.
- Added CLI tests for repeated store-backed invocations, replay rejection, corrupt-store fail-closed behavior, and misuse without `--admit`.
- Extended the Docker replay-admission smoke with a real-container `--replay-store` path and file checks for schema, consumed state, nonce digest storage, no raw nonce, and private permissions.
- Validation at that slice: focused CLI Docker admission tests passed with 5 tests; focused sandbox file-store tests passed with 2 tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 337 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; updated Docker replay-admission smoke passed.
- Remaining production work: define production replay-store path policy or move challenge authority to Vault, add trusted time, and define production audit sink behavior before relying on local replay state for production enforcement.

The current persistable replay guard snapshot slice prepares challenge replay state for durable storage:

- Changed `ProviderChallengeReplayGuard` records to store `provider_challenge_nonce_digest(...)` instead of retaining the raw challenge nonce.
- Added `ProviderChallengeReplaySnapshot`, `ProviderChallengeReplayGuard::snapshots()`, and `ProviderChallengeReplayGuard::restore(...)`.
- Restored guards preserve the full mutation-check tuple: subject, context hash, configured Vault host, probe destinations, nonce digest, validation time, expiry, and consumed status.
- Added tests proving a restored guard accepts the original challenge once, rejects replay after restore, records consumed status in snapshots, and rejects a mutated nonce without storing the raw nonce.
- Current validation: focused sandbox replay-guard tests passed with 4 tests; focused sandbox active-probe admission tests passed with 2 tests; focused CLI Docker active-probe tests passed with 7 tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 331 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; fixture admission, provider challenge, and Docker replay-admission smokes passed; all smoke/build script syntax checks passed; narrowed ASCII and Docker cleanup/image/network checks passed.
- Remaining production work: add an authenticated/permissioned local or Vault-backed durable store, atomic issue/consume, trusted clock, retention/GC, and audit correlation before snapshots become a production challenge service.

Previous Docker active-probe replay-admission slice:

The Docker active-probe replay-admission slice wires real Docker receipt output into replay-owned admission:

- Added `--admit` and `--replay` to `whoathere evidence linux-active-probe-docker`.
- In admission mode, the command issues a nonce/expiry-bound challenge through `ProviderChallengeReplayGuard`, runs or plans the Docker probe against that challenge, consumes the challenge exactly once, and renders `admission_applied`, optional `preconsume`, and `admission` alongside the raw Docker run and active-probe receipt.
- The Docker command still reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`; accepted replay ownership is only admission evidence, not trusted proof material.
- Added CLI tests for Docker admission mode, replay rejection, and replay-without-admission misuse.
- Added `scripts/whoathere-linux-active-probe-docker-admission-smoke.sh`, covering no-network real Docker output, replay rejection without Docker execution, and internal-Vault real Docker output.
- Current validation: focused CLI `linux_active_probe_docker` tests passed with 7 tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 329 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; admission, fixture, provider challenge, provider readiness, endpoint, compatibility, Docker active-probe, Docker replay-admission, and internal-Vault smokes passed; all smoke/build script syntax checks passed; narrowed ASCII and Docker cleanup/image/network checks passed.
- Remaining production work: persist replay guard state across process boundaries with a trusted clock, add image provenance/signing verification, satisfy current-process user namespace isolation, and only then map admitted satisfying receipts into trusted proofs.

Previous replay-owned fixture admission slice:

The replay-owned active-probe admission slice added a single-use challenge admission gate for fixture receipts:

- Added `LinuxActiveProbeAdmission` and `admit_linux_active_probe_receipt`, which consume a submitted challenge through `ProviderChallengeReplayGuard`, parse the active-probe receipt, and accept only when replay ownership and receipt validation both succeed.
- Added `whoathere evidence linux-active-probe-admission --subject <id> --context-hash <hash> --vault-host <host> --profile complete|incomplete|overpermissive [--replay|--unknown-challenge|--mutate-context] [--json]`.
- Added `scripts/whoathere-linux-active-probe-admission-smoke.sh`, covering accepted, replayed, unknown, mutated-context, and incomplete receipt scenarios.

Previous non-root user namespace evidence slice:

The non-root user namespace evidence slice made the Docker active probe safer by default and replaced a hardcoded userns failure with structured evidence:

- Probed OrbStack Docker user namespace behavior: default containers expose a full identity map, Docker rejects `--userns=private` and `--userns=auto`, and nested `unshare -Ur` fails under the hardened seccomp-enabled flags.
- Confirmed nested userns creation can work only with seccomp unconfined locally, including a non-root `0:65532:1` nested map, and rejected that path because it weakens another required proof.
- Changed `evidence linux-active-probe-docker` to run the active probe as Docker user `65532:65532`.
- Updated the local probe image and inline fallback to emit current UID/GID, UID/GID maps, nested-userns attempt status, and nested maps when available.
- Extended the receipt model and JSON/text output with user namespace evidence fields; `user_namespace.isolated=true` is derived only from the current process UID and GID maps being remapped away from host root.
- Added a focused unit test proving a synthetic remapped `0:100000:65536` UID/GID map can satisfy the receipt contract, while the local OrbStack run remains fail-closed with identity maps and nested unshare denied.
- Current validation: focused CLI `linux_active_probe_docker` tests passed with 6 tests; focused sandbox `linux_active_probe` tests passed; local probe image rebuild passed; direct Docker-backed evidence command returned expected exit 20 with `container_user=65532:65532`, identity UID/GID maps, and nested userns denied; default no-network Docker smoke passed; internal-Vault Docker smoke passed; direct `--docker-network bridge` run returned expected deny with `docker_invoked=false`; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 323 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; fixture, provider challenge, provider readiness, endpoint, and compatibility smokes; shell syntax and ASCII checks; Docker cleanup/image-list checks.
- Remaining production work: provide a Linux runtime profile that gives the active probe a real remapped current-process UID/GID map while preserving seccomp/cgroups, then add replay-guard-owned challenge binding, image provenance/signing verification, and trusted-proof mapping rules.

Previous internal-network Vault allowance slice:

The internal-network Vault allowance slice gave the Docker active-probe executor a controlled configured-Vault allow path while preserving fail-closed behavior:

- Added `--docker-network <internal-network>` to `whoathere evidence linux-active-probe-docker`; custom networks are inspected with Docker and refused unless `Internal=true`.
- Updated the local probe script and inline fallback to emit `probe.vault_connect=allowed|denied` only for the configured Vault host supplied by the CLI.
- Changed receipt evidence so a verified internal network plus successful configured-Vault probe records `default_deny_except_configured_vault=true`, `allowed=<configured Vault>`, and denied evidence for every non-Vault challenge destination.
- Expanded receipt JSON with `allowed_probe_destinations` and `denied_probe_destinations` so black-box smokes can prove exact destination handling rather than relying on counts alone.
- Added `scripts/whoathere-linux-active-probe-internal-vault-smoke.sh`, which creates a throwaway internal Docker network, starts an inert Vault fixture, verifies one allowed Vault destination and fourteen denied non-Vault destinations, and confirms the command still exits 20 with `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- Current validation: focused CLI `linux_active_probe_docker` tests passed with 5 tests; local probe image rebuild passed; internal-Vault Docker smoke passed; default no-network Docker smoke passed; direct `--docker-network bridge` run returned expected deny with `docker_invoked=false`; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 322 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; fixture, provider challenge, provider readiness, endpoint, and compatibility smokes; shell syntax and ASCII checks; Docker cleanup/image-list checks.
- Remaining production work: add user namespace evidence, replay-guard-owned challenge binding, image provenance/signing verification, and trusted-proof mapping rules before any receipt can become a launch authorization input.

Previous local Linux active-probe image contract slice:

The local Linux active-probe image contract slice made the Docker executor use a product-owned image contract instead of only an inline shell probe:

- Added `whoathere/probe-images/linux-active-probe/Dockerfile`, `.dockerignore`, and `whoathere-active-probe`; the script emits controlled `probe.*` facts plus `probe.image_contract=whoathere-linux-active-probe.v1`.
- Added `scripts/whoathere-build-linux-active-probe-image.sh`, which builds `whoathere/linux-active-probe:local` from the already-present BuildKit base with `--pull=false`.
- Changed `evidence linux-active-probe-docker` to default to `whoathere/linux-active-probe:local`, prefer `/usr/local/bin/whoathere-active-probe` when present, keep inline fallback support, and render `image_contract` plus `image_contract_valid`.
- Updated `scripts/whoathere-linux-active-probe-docker-smoke.sh` to build/use the local probe image and assert `image_contract_valid=true`.
- Current validation: local image build passed; focused CLI `linux_active_probe_docker` tests passed; direct Docker-backed command returned expected exit 20 with `image_contract_valid=true`; `scripts/whoathere-linux-active-probe-docker-smoke.sh` passed; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 321 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; fixture, provider challenge, provider readiness, endpoint, compatibility, shell syntax, ASCII, image-list, and no-leftover-container checks passed.
- Remaining production work: add user namespace evidence, a configured-Vault allow path, replay-guard-owned challenge binding, and image provenance/signing verification before any receipt can become a trusted proof.

Previous Docker active-probe executor harness slice:

The Docker active-probe executor harness slice made the first real Linux container probe executable while preserving fail-closed behavior:

- `whoathere evidence linux-active-probe-docker --subject <id> --context-hash <hash> --vault-host <host> [--image <image>] [--execute] [--json]` now runs only when `--execute` is explicit.
- Execute mode invokes Docker with `--network none`, `--security-opt no-new-privileges`, `--cap-drop ALL`, `--pids-limit 64`, `--memory 128m`, `--cpus 1`, a bounded timeout, cidfile tracking, and best-effort timeout cleanup.
- The executor parses controlled container `probe.*` facts and emits `linux_active_probe.v1` evidence. On the local BuildKit image it proves Linux execution, no-new-privileges, seccomp filter mode, cgroup limits, network namespace/no-network denial, and all challenge probes denied.
- Current local execution intentionally fails closed because Docker does not prove user namespace isolation and `--network none` denies the configured Vault too. The command always reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- Current validation: focused CLI `linux_active_probe_docker` tests passed; direct Docker-backed command returned expected exit 20; `scripts/whoathere-linux-active-probe-docker-smoke.sh` passed; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 320 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; fixture, provider challenge, provider readiness, endpoint, compatibility, shell syntax, ASCII, and no-leftover-container checks passed.
- Remaining production work: add a purpose-built Linux probe image/runtime that can prove user namespace isolation and default-deny-except-configured-Vault, then bind satisfied receipts to replay-guard-owned challenges before mapping them into trusted proofs.

Previous JSON challenge probe manifest slice:

The JSON challenge probe manifest slice made provider challenge JSON directly consumable by the future active-probe executor:

- Shared challenge JSON rendering now includes exact sorted `probe_destinations` next to `probe_destination_count`.
- `evidence challenge --json`, `evidence providers --json`, and `evidence linux-active-probe-fixture --json` expose the verifier's requested destination set without changing text output, fail-closed status, proof trust, or launch authorization.
- Focused CLI tests now assert configured Vault, public registry, private network, and DNS probe destinations in JSON challenge paths.
- Current validation: focused CLI tests for provider JSON, challenge JSON, and overpermissive active-probe fixture JSON passed; a black-box Python JSON parse confirmed `probe_destination_count == len(probe_destinations)` and expected Vault/public/DNS probes; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 317 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; fixture, provider challenge, provider readiness, endpoint, compatibility, and ASCII smokes passed.
- Remaining production work: implement the real Docker/OrbStack-backed Linux active-probe executor using this `probe_destinations` manifest as input and the existing receipt fixture contract as output.

Previous Linux active-probe fixture validator slice:

The Linux active-probe fixture validator slice made the receipt contract executable without granting authorization:

- `whoathere-sandbox` now has `LinuxActiveProbeFixtureProfile` plus `linux_active_probe_fixture_evidence` for complete, incomplete, and overpermissive fixture profiles.
- `whoathere evidence linux-active-probe-fixture --subject <id> --context-hash <hash> --vault-host <host> --profile complete|incomplete|overpermissive [--json]` validates deterministic fixture evidence through the real receipt parser.
- Complete fixtures return command success for receipt-contract validation only; every fixture output explicitly says `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- `scripts/whoathere-linux-active-probe-fixture-smoke.sh` checks the complete fixture plus incomplete and overpermissive fail-closed profiles without running package managers, mutating OS/network controls, pulling Docker images, or minting trusted proofs.
- Current validation: focused sandbox `linux_active_probe` tests passed; focused CLI `evidence_linux_active_probe_fixture` tests passed; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 317 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; provider challenge, provider readiness, endpoint, compatibility, shell syntax, ASCII, fixture-smoke, and JSON-parse smokes passed.
- Remaining production work: implement the real Linux active-probe executor in a reusable Linux container/endpoint environment, then map only a satisfied replay-guard-owned real receipt into trusted `Verified` proofs.

Previous Linux active-probe receipt slice:

The Linux active-probe receipt slice created the next provider contract needed for real Linux enforcement:

- `whoathere-sandbox` now parses `linux_active_probe.v1` evidence into `LinuxActiveProbeReceipt`, bound to the provider challenge id, subject, context hash, configured Vault host, and required egress probe set.
- The receipt requires Linux user/network namespace isolation, `no_new_privs`, seccomp enforcement, cgroup scoping, default-deny-except-configured-Vault attestation, namespace-only OS/network mutation scope, no package execution, no public-network probe attempt, the configured Vault probe allowed, and every non-Vault challenge probe denied.
- `evidence providers` now renders a Linux `provider_active_probe` text line, and `evidence providers --json` includes `active_probe_receipt` for the Linux provider. Current read-only evidence deliberately reports `satisfied=false` with missing/invalid active-receipt reason codes.
- Current validation: focused sandbox `linux_active_probe` tests passed; focused CLI `evidence_providers` tests passed; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 313 unit tests plus doctests; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; provider challenge, provider readiness, endpoint, compatibility, shell syntax, ASCII, direct `evidence providers --scope linux`, and JSON-parse smokes passed.
- Remaining production work: implement a Linux active probe executor in a Docker/OrbStack-backed fixture, then map only a satisfied replay-guard-owned receipt into trusted `Verified` containment and egress proofs.

Previous launch provider-check diagnostic slice:

The launch provider-check diagnostic slice added a one-shot bridge from launch planning to provider challenge evaluation:

- `launch provider-check` builds the same launch plan as `launch plan`, then evaluates the generated proof challenge against exactly one current-host provider skeleton.
- Output keeps the normal blocked launch-plan fields and appends `launch_provider_check_*` diagnostics for status, provider, challenge ID, subject, context hash, Vault host, probe count, containment/egress proof status, satisfaction, reason codes, and exit code.
- The command is diagnostic-only; it does not run package managers, materialize runtime directories, mutate OS/network state, run public probes, fetch registries, mint proofs, or change `execution_allowed=false`.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli launch_provider_check -- --nocapture` passed; smoke-ran `launch provider-check --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci` and confirmed expected exit 20 plus `launch_provider_check_status=fail_closed`; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 311 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; provider challenge, provider readiness, endpoint, compatibility, and shell syntax smokes passed.
- Remaining production work: replace skeleton provider attempts with real macOS/Linux provider collectors and define replay-guard ownership before any provider-check result can influence launch authorization.

Previous launch-to-provider challenge bridge slice:

The launch-to-provider challenge bridge slice connected blocked launch plans to provider diagnostics:

- `launch plan` now renders `proof_challenge_context_hash` alongside challenge ID, subject, Vault host, probe count, expiry, nonce presence, and validity.
- When a proof challenge exists, launch output includes `provider_challenge_command=whoathere evidence challenge --scope current ...` with shell-safe subject/context/Vault values.
- The command is rendering-only; launch planning does not call providers, mint proofs, mutate OS/network state, or alter `execution_allowed=false`.
- Current validation: focused launch CLI test passed; smoke-ran `launch plan --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci` and confirmed expected exit 20 plus the provider challenge command; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 310 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; provider challenge, provider readiness, endpoint, and compatibility smokes passed.
- Remaining production work: replace copy/paste provider diagnostics with an internal provider-evaluation path only after real providers can satisfy the explicit challenge contract under replay-guard ownership.

Previous explicit provider challenge slice:

The explicit provider challenge slice added a launch/provider contract command without enabling execution:

- `whoathere evidence challenge --subject <id> --context-hash <hash> --vault-host <host> [--json] [--scope current|linux|macos]` evaluates one local provider against a caller-supplied challenge.
- The command rejects missing subject, missing context hash, missing Vault host, invalid scope, and multi-provider scope as misuse.
- Text and JSON outputs include the generated challenge, provider challenge attempt, containment proof summary, egress proof summary, status, and exit code.
- Current skeleton providers return `status=fail_closed`, `exit_code=20`, and unsatisfied challenge reasons such as provider-unimplemented, missing egress probes, and non-fresh proof material.
- `scripts/whoathere-provider-challenge-smoke.sh` checks the JSON contract for current-host challenge evaluation and asserts the expected fail-closed attempt.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli` passed with 75 CLI tests; text and JSON `evidence challenge` smokes returned expected exit 20; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 310 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `scripts/whoathere-provider-challenge-smoke.sh`; `scripts/whoathere-provider-smoke.sh`; `scripts/whoathere-endpoint-smoke.sh`; `scripts/whoathere-compat-smoke.sh`; shell syntax checks.
- Remaining production work: connect real provider collectors to this challenge contract, then thread successful provider attempts into launch planning while keeping high-risk package-manager execution denied until every proof gate passes.

Previous provider readiness hardening slice:

The provider readiness hardening slice made provider diagnostics more conservative and easier to regression-test:

- Linux and macOS readiness now require `provider_target_matches_host=true` before local prerequisites can be considered present.
- Linux readiness now records read-only namespace baseline links plus common namespace and packet-filter tooling signals, and it requires namespace creation plus packet-filter tooling before `required_primitives_present=true`.
- macOS readiness keeps VM isolation as the strong-control candidate, keeps beta containment explicit, and remains blocked when required telemetry/proof verification evidence is missing.
- `scripts/whoathere-provider-smoke.sh` runs `evidence providers --json --require-ready --scope current`, expects exit 20, and asserts fail-closed/read-only posture: no active verification, package execution, OS mutation, network mutation, or public network probing.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-sandbox -p whoathere-cli` passed with 36 sandbox tests and 72 CLI tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 307 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `scripts/whoathere-provider-smoke.sh`; `scripts/whoathere-endpoint-smoke.sh`; `scripts/whoathere-compat-smoke.sh`; shell syntax checks.
- Remaining production work: replace these fail-closed provider skeletons with real provider-owned proof collectors that bind launch-subject containment and Vault-only egress to the challenge before any high-risk package-manager execution can be considered.

Previous endpoint interception smoke slice:

The endpoint interception smoke slice added a repeatable wiring check around the local developer workflow:

- `scripts/whoathere-endpoint-smoke.sh` creates temp workspace and shim directories, then runs `endpoint setup`, `shim install`, and PATH-shadowed package-manager commands.
- The setup step is expected to exit 20 with `status=fail_closed`, `provider_scope=current`, and `ready_for_high_risk_execution=false` until real provider verification exists.
- The shim step verifies materialized npm/npx/pip/pip3 shims and confirms they call `whoathere protect --execute <tool> -- "$@"`.
- The PATH step verifies `npm` and `pip` resolve to the temp shims, then runs expected-denied `npm ci` and `pip install fixture` through those shims.
- Both intercepted commands deny at the launch proof gate with `launch_plan_status=blocked` and `execution_reason=launch_plan_blocked`; npm/pip themselves do not execute.
- Current validation: `bash -n scripts/whoathere-endpoint-smoke.sh`; `scripts/whoathere-endpoint-smoke.sh`; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 305 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`; `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`; `scripts/whoathere-compat-smoke.sh`; `bash -n scripts/whoathere-compat-smoke.sh`; ASCII scan.
- Remaining production work: keep this as the endpoint wiring regression while replacing fail-closed provider skeletons with real macOS/Linux containment and Vault-only egress proof collectors.

Previous endpoint setup diagnostics slice:

The endpoint setup diagnostics slice added a setup/verification command around shims, env defaults, and provider readiness:

- `whoathere endpoint setup --shim-dir <dir> --workspace <path> --vault-origin <url> [--policy <path>] [--audit-path <path>] [--include-python]` renders a complete local endpoint setup plan.
- The command also accepts `WHOATHERE_SHIM_DIR`, `WHOATHERE_WORKSPACE`, `WHOATHERE_VAULT_ORIGIN`, `WHOATHERE_POLICY`, and `WHOATHERE_AUDIT_PATH` as defaults; explicit flags remain authoritative.
- It prints the `shim install` command, PATH export, WhoaThere env exports, current provider platform, and the exact provider readiness command.
- It is diagnostic-only: `mutation=false`, no shell profile edits, no shim materialization, no package-manager execution, and no provider verification claim.
- It exits 20 with `status=fail_closed` while `evidence providers --scope current --require-ready` cannot verify the current OS provider.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli` passed with 72 CLI tests; endpoint setup smoke with temp shim/workspace env defaults returned expected exit 20 and rendered setup commands; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 305 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`, `scripts/whoathere-compat-smoke.sh`, and ASCII scan passed.
- Remaining production work: once real providers can verify current-host enforcement, use this command as the developer/CI readiness gate before adding the shim directory to PATH.

Previous endpoint shim execution/defaults slice:

The endpoint shim execution/defaults slice made PATH interception more representative of real install attempts:

- Materialized shims now invoke `whoathere protect --execute <tool> -- "$@"` instead of preview-only `protect <tool> --`.
- `protect` now accepts environment defaults for `WHOATHERE_WORKSPACE`, `WHOATHERE_VAULT_ORIGIN`, `WHOATHERE_POLICY`, and `WHOATHERE_AUDIT_PATH`; explicit CLI flags override environment values.
- No environment variable enables execution. Execution request still comes from the generated shim or explicit `--execute`, and high-risk install execution remains blocked until launch proofs verify containment and Vault-only egress.
- `shim install --dry-run` now reports the supported env default variables.
- Real PATH shim smoke passed: materialized shims in a temp directory, put that directory first on PATH, set workspace/Vault env defaults, ran `npm ci`, and verified WhoaThere returned exit 20 after source scan succeeded and the launch proof gate blocked with `egress_verified_proof_required`.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli` passed with 69 CLI tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 302 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`, `scripts/whoathere-compat-smoke.sh`, real PATH shim smoke, and ASCII scan passed.
- Remaining production work: add a documented setup command or helper that creates a shim directory, exports env defaults in a shell-safe way, and verifies the current endpoint provider readiness before developers add the shim directory to PATH.

Previous compatibility smoke reliability slice:

The compatibility smoke reliability slice hardened the local-dev server and npm/pip smoke harness:

- A transient `ECONNREFUSED`/timeout during `scripts/whoathere-compat-smoke.sh` exposed that accepted streams from the nonblocking dev-server listener could fail immediate reads on macOS.
- `whoathere-vault-dev` now sets accepted streams back to blocking mode and applies a bounded read timeout before parsing the HTTP request.
- `scripts/whoathere-compat-smoke.sh` now has Python-backed command timeouts for npm, pip, and metadata checks, detects server death during readiness, bounds server-exit waits, and prints server logs when startup, package-manager execution, route-log checks, or server exit fail.
- The script now explicitly returns after npm/pip timeout/failure before attempting metadata checks, avoiding misleading secondary errors.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-vault-dev` passed with 58 Vault dev tests; `bash -n scripts/whoathere-compat-smoke.sh` passed; `scripts/whoathere-compat-smoke.sh` passed after the server read-stabilization fix; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 300 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`, and ASCII scan passed.
- Remaining production work: convert this script into an owned CI integration target with explicit environment prerequisites for npm, pip, Python, loopback binding, and package-manager timeout budgets.

Previous scoped provider readiness slice:

The current scoped provider readiness slice made provider diagnostics usable for both fleet-wide and current-host checks:

- `whoathere evidence providers` now accepts `--scope all|current|linux|macos`; `all` remains the default for backwards-compatible fleet-wide diagnostics.
- Text diagnostics render `provider_scope` and `current_provider_platform`; scoped runs filter provider rows before readiness gating.
- JSON diagnostics render top-level `provider_scope` and `current_provider_platform`; scoped runs filter provider objects before calculating `provider_ready`.
- `--require-ready --scope current` now checks only the current endpoint provider, but still fails closed because real containment/egress verifiers are not implemented.
- Invalid scopes fail closed as CLI misuse with reason `invalid_provider_scope` and exit 64.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli` passed with 67 CLI tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 300 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; scoped command smokes covered current-host fail-closed readiness, Linux-only text output, and invalid-scope misuse; `scripts/whoathere-compat-smoke.sh` passed on rerun after one transient loopback `ECONNREFUSED`.
- Remaining production work: wire scoped readiness into CI/developer setup guidance after real OS providers exist, and decide whether enterprise policy should require `all` scope for fleet conformance versus `current` scope for endpoint admission.

Previous provider posture evidence slice:

The current provider posture evidence slice tightened local isolation diagnostics without changing authorization:

- `whoathere-sandbox` now emits `provider_evidence_schema=local_provider_readiness.v1`, host platform, target platform, target/host match, active-verification state, package-execution state, OS-mutation state, network-mutation state, and public-network-probe state for Linux/macOS local providers.
- `local_provider_evidence_posture_from_evidence` parses those signals into a structured contract for CLI/reporting/tests.
- `whoathere evidence providers` now renders a `provider_posture` line for each provider.
- `whoathere evidence providers --json` now renders a `posture` object beside each provider's challenge attempt, readiness, verification plan, and raw redacted evidence.
- The posture remains diagnostic-only: provider trust is still `None`, containment/egress proof status remains `Missing`, `--require-ready` still exits 20, and protected install execution remains gated.
- Current validation: focused `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-sandbox -p whoathere-cli` passed with 34 sandbox tests and 64 CLI tests; full `cargo test --manifest-path whoathere/Cargo.toml` passed with 297 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`, ASCII scan, and `scripts/whoathere-compat-smoke.sh` passed; `cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers` rendered `provider_posture` lines; `cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --json --require-ready` returned expected exit 20 with `status=fail_closed` and explicit no-active/no-mutation posture fields.
- Remaining production work: implement real Linux/macOS collectors that can actively verify same-subject containment and default-deny Vault-only egress before enabling high-risk install execution.

Previous repeatable compatibility smoke harness slice:

The current repeatable compatibility smoke harness slice turned the manual npm/pip proof into a rerunnable script:

- Added `scripts/whoathere-compat-smoke.sh`.
- The script picks loopback ports, starts bounded local-dev Vault servers, waits for `/healthz`, runs npm and pip in fresh temp directories, and verifies installed fixture metadata without importing Python package code.
- npm runs with `--ignore-scripts --no-audit --no-fund`, an isolated temp cache, and the local Vault registry URL.
- pip runs with `--no-deps --disable-pip-version-check`, an isolated temp target/cache, and the local Vault Simple API URL.
- Each bounded server expects exactly three requests: health check plus metadata plus archive. The script verifies `served_requests=3`, sanitized request-body/response-body flags, and the expected route kinds.
- Current validation: `scripts/whoathere-compat-smoke.sh` passed; `bash -n scripts/whoathere-compat-smoke.sh` passed; full `cargo test` passed with 297 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, ASCII scan, and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.
- Remaining production work: decide whether this remains a script, becomes a `cargo xtask`, or becomes an ignored integration test in CI that can run only where npm/pip and loopback binding are available.

The current Host-aware local-dev registry compatibility slice removed the fixed-port assumption from package-manager metadata:

- Compat metadata renderers now derive absolute package byte URLs from a validated loopback `Host` header when the bounded dev server receives a real request.
- Socketless `vault dev-http` still defaults to `http://127.0.0.1:4873` because it intentionally rejects synthetic `Host` headers.
- Allowed Host values are limited to loopback authorities with explicit ports: `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>`.
- Public, malformed, credential-like, path-like, whitespace, and missing-port Host values fail closed with `registry_compat_host_not_loopback` instead of being reflected into package metadata.
- Real npm and pip compatibility smokes passed against non-default ports `127.0.0.1:48743` and `127.0.0.1:48742`; both bounded servers exited after two requests and logged only sanitized metadata/file request summaries.
- Current validation: focused vault-dev/CLI tests passed with 64 CLI tests and 58 Vault dev tests; dynamic-port npm/pip smokes passed; full `cargo test` passed with 297 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, ASCII scan, and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.
- Remaining production work: convert the temp-dir smokes into an automated integration harness with allocated ports and provider-gated execution boundaries.

The current safe package archive compatibility slice replaced placeholder compat bytes with structurally valid generated fixtures:

- `/v1/registry-compat/npm/...` now renders an npm packument with a `.tgz` tarball URL and SRI `sha256-...` integrity computed from a deterministic generated archive.
- `/v1/registry-compat/pypi/simple/...` now renders a wheel filename with a standard `#sha256=` fragment computed from a deterministic generated wheel.
- The generated npm archive is a gzip tar containing only `package/package.json` and `package/index.js`, with an empty scripts object and no lifecycle hooks.
- The generated PyPI archive is an uncompressed wheel containing `METADATA`, `WHEEL`, `RECORD`, and a harmless `fixture/__init__.py`; the smoke inspected installed files without importing the package.
- Both archive families still flow through the exact promoted artifact/cache-key lookup and immutable cache headers; simulation routes continue to preserve the older 25-byte inert fixture behavior for regression coverage.
- Current validation: focused vault-dev/CLI tests passed with 64 CLI tests and 55 Vault dev tests; socketless CLI smokes passed for npm packument, npm gzip range bytes, PyPI Simple metadata, and PyPI wheel `HEAD`; real temp-dir npm and pip smokes passed against a bounded loopback Vault server with npm lifecycle scripts disabled and pip dependency resolution disabled; full `cargo test` passed with 294 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.
- Remaining production work: turn these local fixture contracts into durable authenticated registry endpoints, move package-manager smokes into an automated integration harness, and only enable protected real install workflows after OS containment and egress proof providers are verified.

The previous package-manager-shaped registry compatibility slice added explicit local-dev aliases for npm and PyPI client compatibility research:

- npm-compatible local-dev routes now live under `/v1/registry-compat/npm/...`; PyPI Simple/file-compatible local-dev routes now live under `/v1/registry-compat/pypi/...`.
- Compat metadata routes do not need `?promoted=true`; they are intentionally fixed to the promoted inert fixture and fail closed for unknown packages.
- Compat package-byte aliases reuse the exact promoted artifact/cache-key lookup path, immutable cache validators, conditional request behavior, `HEAD`, and single byte-range handling from the simulation routes.
- Sanitized server request logs classify compat routes as npm metadata, npm tarball, PyPI metadata, or PyPI file categories instead of falling back to `other`.
- Validation at that slice: focused vault-dev/CLI tests passed with 64 CLI tests and 53 Vault dev tests; socketless CLI smokes passed for npm packument, npm range tarball, PyPI Simple page, and PyPI file `HEAD`; full `cargo test` passed with 292 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, ASCII scan, and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.
- Remaining production work: replace fixed local-dev fixture aliases with authenticated tenant-aware package-manager registry endpoints, durable promoted-object storage, real package fixtures, and end-to-end npm/pip client compatibility tests after containment and egress proof providers are implemented.

The current conditional ETag slice added `If-None-Match` behavior for promoted package bytes:

- Conditional handling runs only after the exact promoted artifact/cache-key lookup succeeds.
- Matching strong ETags, matching weak ETags, and `If-None-Match: *` return `304 Not Modified`, cache validators, `Accept-Ranges: bytes`, and no body bytes.
- Mismatched validators continue to normal byte serving.
- A matching validator takes precedence over Range and returns 304 instead of 206.
- Current validation: focused vault-dev/CLI tests passed; socketless CLI smokes passed for matching 304 and mismatched 200 behavior; full `cargo test` passed with 286 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, ASCII scan, and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.

The current `vault dev-http` synthetic-header slice made compatibility tests runnable without socket binds:

- `vault dev-http` now accepts repeated `--header <name:value>` and `--header=<name:value>` options.
- Headers are validated before routing; malformed lines, CR/LF injection, empty names/values, invalid header names, and simulator-owned `Host`/`Content-Length` headers fail closed.
- The existing optional body behavior is preserved for POST-style simulations.
- Socketless Range simulation now covers the same byte-range path as the bounded server: `--header 'Range: bytes=6-10'` returns 206 and body `cache`.
- Current validation: focused vault-dev/CLI tests passed; CLI smokes passed for header-driven 206 partial content and reserved-header fail-closed denial; full `cargo test` passed with 282 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, ASCII scan, and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.

The current sanitized server request-log slice added observability without payload capture:

- `DevServerSummary` now carries sanitized per-request entries for the bounded loopback server.
- Each entry records method, route kind, status code, range state, declared response body bytes, actual wire response body bytes, and explicit `request_body_logged=false` / `response_body_logged=false` flags.
- The CLI renders `request_log_count` plus one structured block per served request.
- The log intentionally does not include request bodies, response bodies, authorization headers, registry tokens, package bytes, or full target URLs.
- Current validation: focused vault-dev/CLI tests passed; full `cargo test` passed with 279 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`, ASCII scan, and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; an escalated `vault dev-serve` plus `curl` smoke with a synthetic sensitive header returned 206 partial content while the server summary logged only sanitized fields and no secret/body content.
- Remaining production work: durable audit/request logging with tenant authz, retention, signing, and redaction policy.

The current package-byte range slice added single-range serving after promoted-cache lookup:

- Range parsing is header-based and supports a single `bytes=start-end`, `bytes=start-`, or `bytes=-suffix` range.
- Normal promoted byte responses now advertise `Accept-Ranges: bytes` only because range behavior exists.
- Valid ranges return `206 Partial Content`, exact sliced body bytes, and `Content-Range`.
- `HEAD` plus `Range` returns the partial content headers and declared partial length without body bytes.
- Unsupported units, malformed ranges, multiple ranges, empty-object ranges, and unsatisfiable ranges fail closed with `416 Range Not Satisfiable`, `Content-Range: bytes */25`, and `served=false`.
- Current validation: focused vault-dev/CLI tests passed; full `cargo test` passed with 278 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; escalated `vault dev-serve` plus `curl` smokes covered both 206 partial content and 416 fail-closed paths.
- Remaining production work: serve durable tenant-authenticated promoted object bytes, add auth/TLS, conditional request behavior if needed, request logging, and real npm/pip compatibility fixtures.

The current package-byte HTTP compatibility slice added cache validators and HEAD behavior for promoted-byte routes:

- `HttpResponse` now carries explicit extra headers, while `HttpBody::head_only` can declare a content length without appending body bytes.
- npm tarball and PyPI file routes add `Cache-Control: private, max-age=31536000, immutable`, a strong SHA-256 ETag derived from the artifact digest, and `X-Content-Type-Options: nosniff`.
- `HEAD` requests for promoted npm/PyPI byte routes perform the same promoted artifact/cache-key lookup as `GET`, then return metadata with no body bytes.
- This slice initially did not advertise `Accept-Ranges`; the later package-byte range slice adds validated `206/416` behavior before turning that header on.
- Current validation at the time: focused vault-dev/CLI tests passed; full `cargo test` passed with 273 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; `vault dev-http HEAD` smokes passed for npm and PyPI; the escalated `vault dev-serve` plus `curl -fsSI` smoke returned the expected headers and exited with `served_requests=1`.
- Remaining production work: serve durable tenant-authenticated promoted object bytes, add auth/TLS, request logging, and real npm/pip compatibility fixtures.

The current binary-safe local-dev HTTP response slice removed the string-backed body limitation:

- `HttpResponse` now stores an `HttpBody` byte buffer, while text routes still use `HttpBody::from_text` for readable assertions.
- `to_http_wire_bytes` emits headers plus exact body bytes; `to_http_wire` remains a lossy text convenience for CLI display.
- The bounded dev server writes `to_http_wire_bytes`, so future package archives do not have to round-trip through UTF-8 strings.
- A regression test proves non-UTF-8 bytes are preserved exactly on the wire, including `Content-Length`.
- Current validation: focused vault-dev/CLI tests passed; full `cargo test` passed with 271 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; the escalated `vault dev-serve` plus curl smoke was rerun after the refactor and still returned `inert cache fixture bytes` with `served_requests=1`.
- Remaining production work: serve durable tenant-authenticated promoted object bytes, add auth/TLS, request logging, and real npm/pip compatibility fixtures.

The current bounded local-dev Vault server slice added real loopback HTTP serving without introducing a long-running blocker:

- `vault dev-serve` now binds only to loopback addresses, serves through the same local-dev router as `vault dev-http`, and reports bind address, served request count, max request count, and idle timeout.
- The server exits after `--max-requests` or `--idle-timeout-ms`; `--max-requests=0`, non-loopback binds, bind failures, accept/read/write failures, and invalid bind addresses fail closed with reason codes.
- Unit tests cover parser defaults/options, zero-request fail-closed behavior, non-loopback denial, idle timeout, and a real loopback request when the environment permits binding.
- Current validation: focused vault-dev/CLI tests passed; full `cargo test` passed with 270 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; an escalated smoke ran `vault dev-serve` on `127.0.0.1:48731`, fetched the inert npm tarball route with curl, and confirmed the server exited after one request.
- Remaining production work: add TLS/auth, durable storage, real package-manager compatibility tests, and deployment supervision. This command is still local-dev only.

The current local-dev promoted-byte registry serving slice added exact-match inert byte routes:

- npm tarball and PyPI file simulation routes now serve the fixed local-dev inert cache payload only after recreating the promoted cache path and calling `promoted_bytes_for_artifact`.
- The byte path binds artifact identity to the canonical cache object key; a deliberate cache-key mismatch smoke fails closed with `cache_promoted_object_key_mismatch` and `served=false`.
- Promoted PyPI Simple metadata now links to the local-dev file route instead of a public index URL.
- The fixed local-dev generation byte length was corrected to 25 bytes to match the SHA-256 verified inert payload.
- Current validation: focused vault-dev/registry/cache/CLI tests passed; full `cargo test` passed with 264 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; smokes covered npm byte serving, npm cache-key mismatch denial, PyPI byte serving, and promoted PyPI metadata linking.
- Remaining production work: replace fixed inert bytes with durable tenant-authenticated promoted object storage and keep real package-manager execution gated until OS containment and egress proofs verify.

The current local-dev registry facade slice added promoted-only metadata simulation routes:

- Local-dev HTTP now has npm and PyPI registry simulation metadata routes under `/v1/registry-simulations`.
- Unpromoted artifacts fail closed with HTTP 503 and `artifact_not_promoted`.
- Promoted npm renders packument metadata with a local tarball URL and no public registry URL; promoted PyPI renders Simple HTML with a local href and no public index URL.
- The routes do not fetch registries, execute package managers, detonate artifacts, or serve package bytes.
- Current validation: focused vault-dev/registry/CLI tests passed; full `cargo test` passed with 258 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; registry smokes covered unpromoted npm denial, promoted npm metadata, and promoted PyPI metadata.
- Remaining production work: wire routes to a real persistent admission/cache store, tenant authz, and content-addressed byte serving only after promotion and exact artifact/key lookup are enforced.

The current optional Python shim slice made `python -m pip` interception materializable without changing safe defaults:

- `shim install` now parses `--include-python`; default materialization still writes only `npm`, `npx`, `pip`, and `pip3`.
- `materialize_unix_shims_with_options` writes optional `python` and `python3` shims only when explicitly requested, while existing `materialize_unix_shims` remains backward-compatible and default-safe.
- Dry-run output reports `include_python=<bool>` and continues to list python/python3 as optional targets so operators understand the tradeoff before mutating a shim directory.
- Tests cover parsing the opt-in flag, default absence of python/python3 files, and explicit materialization of python/python3 shims; the existing command classifier and package-identity/source gates already handle `python -m pip`.
- Current validation: focused CLI tests passed with 57 tests; full `cargo test` passed with 255 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; dry-run and opt-in materialization smokes passed into `/private/tmp/whoathere-python-shim-smoke-codex`.
- Remaining production work: design a non-breaking pass-through Python shim or launcher discovery mechanism before recommending python/python3 shims broadly; the current mode is intentionally explicit because it can intercept ordinary Python invocations.

The current egress probe matrix slice broadened Vault-only verification coverage:

- `mandatory_vault_only_probe_destinations` now includes public registries, GitHub, cloud metadata/link-local, loopback, private IPv4, IPv6 loopback/ULA/link-local, and public DNS destinations.
- `vault_only_probe_destinations` centralizes configured-Vault plus mandatory probe construction, sorting, and deduplication so challenge creation and test-only egress proofs cannot drift.
- Verified egress tests now require the expanded matrix and assert private IPv4, IPv6, and DNS probes are denied before a Vault-only proof can be considered verified.
- CLI launch/provider diagnostics now render `probe_destination_count=15` for the standard local challenge with a non-mandatory configured Vault host.
- Current validation: focused sandbox/launch/CLI tests passed; full `cargo test` passed with 253 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; `evidence providers --json` and `launch plan --execute ... --egress-enforced --containment-available npm -- ci` smokes passed with fail-closed 15-probe challenge output.
- Remaining production work: real OS providers must perform and independently attest equivalent deny checks at the packet-filter/network-boundary layer, including DNS behavior and IPv6 handling.

The current provider challenge replay-control slice added single-use challenge mechanics:

- `ProviderVerificationChallenge` now includes a nonce and expiry timestamp, and challenge ids bind subject, SHA-256 context hash, Vault host, validation time, expiry, nonce, and required egress probes.
- `ProviderChallengeReplayGuard` issues nonce-backed challenges, records issued challenge state in memory, accepts first use only, rejects unknown, expired, replayed, and mutated challenges, and can prune expired entries.
- Challenge validity now has both static checks and `valid_at`/`reason_codes_at` freshness checks; invalid nonce and expiry shapes fail closed before proof acceptance.
- CLI launch and provider JSON diagnostics render `proof_challenge_expires_at`, `proof_challenge_nonce_present`, `expires_at_unix_seconds`, and `nonce_present` without exposing raw nonce values in ordinary output.
- Current validation: focused sandbox/launch/CLI tests passed; full `cargo test` passed with 252 unit tests plus doctests; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed; `evidence providers`, `evidence providers --json`, and `launch plan --execute ... --egress-enforced --containment-available npm -- ci` smokes passed with fail-closed challenge output.
- Remaining production work: replace the in-memory guard with durable per-launch/provider storage, use a trusted clock source, and wire challenge consumption into real provider collectors and launch proof acceptance.

The current challenge-first proof-provider SPI slice closed the remaining full-challenge API gap:

- `whoathere-sandbox` now exposes `ProviderChallengeProofs`, `prove_containment_for_challenge`, `prove_egress_for_challenge`, and `prove_challenge`, so real providers receive the complete `ProviderVerificationChallenge` before minting containment or egress proof attempts.
- The test-only provider now derives containment and egress proof subject/context from the challenge, not its stored defaults; a regression test verifies a stale provider instance still answers from the challenge object.
- Linux, macOS, and generic fail-closed providers now bind unavailable challenge attempts to the challenge subject/context and include challenge id, subject, context hash, Vault host, and probe count in proof evidence while still returning `Missing` statuses.
- CLI provider diagnostics now fail closed for unimplemented providers, missing egress probes, and non-fresh proofs rather than relying on accidental subject/context mismatches.
- That slice validation: focused sandbox tests passed with 31 tests; focused sandbox/launch/CLI tests passed; `evidence providers`, `evidence providers --json`, and `launch plan --execute ... --egress-enforced --containment-available npm -- ci` smokes passed with fail-closed challenge output; full `cargo test` passed with 250 unit tests plus doctests at the time; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.
- Remaining production work after the replay-control slice: implement real OS-specific collectors behind this SPI, replace in-memory replay state with durable trusted-clock storage, and independently attest actual default-deny egress rule installation.

The current proof-provider challenge slice hardened launch proof binding:

- `whoathere-sandbox` now creates deterministic provider verification challenges bound to launch subject, SHA-256 context hash, configured Vault host, validation time, and mandatory egress probes.
- `whoathere-launch` now emits SHA-256 launch/source fingerprints and requires verified containment and egress proofs to match the generated challenge subject, share provider id/platform/rule generation, match the launch context hash, and remain fresh before runtime materialization.
- Egress verification now requires explicit `egress.default_deny_except_configured_vault.attested=true` evidence in addition to Vault-positive and non-Vault-negative probes, so finite probes alone cannot claim Vault-only enforcement.
- `whoathere evidence providers` text/JSON output now includes challenge attempts and fail-closed reason codes; `launch plan --execute` returns deny when install execution remains disabled even if planning is otherwise possible.
- Subagent review found challenge-subject, replay/session, FNV, finite-probe, and exit-code issues. This slice remediated challenge-subject enforcement, provider session checks, SHA-256 binding, default-deny egress attestation, missing requested-probe checks, and execute-mode exit semantics. Remaining production work after the later SPI slice: OS-specific collectors must implement the challenge-first hooks and use trusted wall-clock/nonce persistence.
- That slice validation: focused sandbox/launch/CLI tests passed; `evidence providers` and `launch plan --execute ... --egress-enforced --containment-available npm -- ci` smokes passed with fail-closed challenge output; full `cargo test` passed with 248 unit tests plus doctests at the time; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.

The current job-log slice added immutable sanitized job-log receipts:

- `whoathere-job-log` provides an in-memory append-only store for sanitized job summaries keyed by job id and log digest.
- The store verifies canonical `sha256:` log digests, parsed summary fields, job/profile/artifact/cache identity, execution/network/detonation false markers, raw-log false markers, and same-job immutability.
- The static manifest producer now exposes structured `raw_log_captured=false`, rejects control-character metadata, and prevents unsafe metadata from forging summary lines.
- The local-dev static manifest route uses a process-lifetime in-memory log store and fails closed on raw-log capture, tampered log digests, and same-job rewrites.
- That slice validation: focused detector/job-log/vault-dev tests passed; route smokes passed for clean, malicious, raw-log, and tampered-digest cases; full `cargo test` passed with 239 unit tests plus doctests at the time; `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` and `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passed.

The latest implementation slice replaced placeholder proof booleans with typed proof objects:

- `ContainmentProof` and `EgressProof` distinguish `Missing`, `OperatorAsserted`, and `Verified`.
- The verified egress verifier requires the configured Vault host to be allowed and mandatory public/metadata/loopback non-Vault destinations to be denied.
- Launch plans now verify egress and containment proof before runtime config materialization for high-risk workflows.
- CLI `--containment-available` and `--egress-enforced` render as `OperatorAsserted`; they are diagnostic flags only and still block high-risk install planning.
- `protect --execute --workspace --vault-origin npm -- ci` uses missing proofs until a trusted provider exists, so it remains fail-closed.

The continuation slice added proof provider SPI and replay hardening:

- `ProofProvenance` records provider id/version, platform, mechanism, trust domain, and evidence count without dumping raw rules or secrets.
- `ProofSubject` binds containment and egress proofs to a launch subject; launch plans block mismatched proof subjects before runtime materialization.
- `EgressPolicyScope::DefaultDenyExceptConfiguredVault` is required before egress can be verified.
- Verified proof minting is sandbox-internal. Test-only verified helpers are available only behind the non-default `whoathere-sandbox/test-support` feature used by launch unit tests.
- CLI/protect output includes proof subject, provider, mechanism, trust, egress scope, evidence count, and reason code.

The current continuation slice added proof freshness metadata:

- `ProofProvenance` now records verified-at, expires-at, context hash, and rule generation ID.
- Launch requests validate proof freshness at a deterministic validation time and block `proof_expired_or_not_yet_valid` before runtime materialization.
- CLI/protect output includes freshness and context metadata summaries for proof debugging.
- Test-support expired proofs exercise stale-proof blocking without adding fake providers to normal builds.

The latest continuation slice added deterministic launch/source fingerprints:

- `whoathere-launch` originally computed deterministic summaries for sanitized launch context and source scan reports; the proof-provider challenge slice later upgraded security-binding fingerprints to canonical `sha256:` digests.
- Launch plans store `launch_context_hash` and `source_scan_hash` before runtime materialization.
- `whoathere launch plan` renders `launch_context_hash` and `source_scan_hash`; `protect --execute` renders the corresponding launch-plan hashes.
- These hashes are binding metadata for future provider evidence, not a cryptographic trust claim.

The current continuation slice added guarded cleanup execution:

- `cleanup_runtime_plan` removes cleanup-owned paths in reverse ownership order.
- Cleanup refuses runtime roots outside the OS temp directory, runtime roots without a `whoathere` prefix, and any owned path outside the runtime root.
- Cleanup result reporting separates removed paths, refused paths, and reason codes.

The latest continuation slice added proof and cleanup audit binding:

- `whoathere-audit` now renders proof summaries, launch/source hashes, and cleanup summaries in JSONL records.
- `whoathere launch audit` shares launch-plan construction and can append a JSONL record with `--audit-path`.
- Audit output stores proof summary counts and redacted metadata, not raw provider evidence or secrets.
- `launch audit` does not execute package managers, run lifecycle scripts, materialize runtime for failed proof gates, or run cleanup.

The current continuation slice added protect audit append:

- `protect --audit-path` parses both split and equals-form audit paths.
- Source-scan deny branches append a redacted `protect-source-gate` JSONL record with source-scan reason codes before refusing execution.
- Launch-gate deny branches append the same proof/hash/cleanup-summary launch audit record used by `launch audit`.
- Focused tests verify persisted JSONL, secret redaction, source-gate deny auditing, and launch-gate deny auditing without spawning package managers or materializing runtime.

The current cleanup slice added explicit cleanup reporting/execution:

- Runtime materialization now writes a private `.whoathere-cleanup.manifest` beside generated runtime config and includes it in cleanup-owned paths.
- `whoathere launch cleanup --manifest <path>` reports cleanup scope without mutation by default; `--execute` invokes guarded cleanup and can append a cleanup audit summary.
- Cleanup now rejects parent-directory escape components before deletion, in addition to non-WhoaThere temp roots and paths outside the runtime root.
- Focused tests cover cleanup manifest round-trip, report-only behavior, execute-with-audit behavior, and parent-directory escape refusal.

The current fake-provider harness slice added provider-contract test plumbing:

- `whoathere-sandbox/test-support` now exposes a `TestOnlyProofProvider` implementing the real `ProofProvider` trait.
- The harness binds containment and egress proofs to the same launch subject and appends mandatory default-deny egress probes.
- `whoathere-launch` has an integration-style test proving fake verified proofs can materialize a private runtime and cleanup manifest while install execution remains disabled.
- This is not a production provider and is unavailable from normal builds.

The current proof-context binding slice added replay protection:

- `whoathere-launch` exposes a deterministic preview helper for launch context hashes.
- Trusted provider provenance can now carry a specific context hash and rule generation ID.
- Launch planning blocks `proof_context_hash_mismatch` before runtime materialization when verified containment or egress proof provenance does not match the current launch context hash.
- Focused tests cover context-bound fake-provider planning and stale-context proof denial.

The current provider skeleton slice added fail-closed collector entrypoints:

- `LinuxLocalProofProvider` and `MacosLocalProofProvider` implement the real `ProofProvider` trait.
- Both providers return `Missing` proofs with platform/mechanism-specific unimplemented reason codes.
- Tests lock in that the skeletons cannot permit high-risk containment or Vault-only egress until real collectors produce trusted evidence.

The current read-only provider evidence slice added local capability probes:

- Linux provider provenance records read-only `/proc` signals for seccomp/no-new-privs, namespace links, cgroup, user namespace clone configuration, and Landlock ABI availability when present.
- macOS provider provenance records read-only framework/tool path presence for Hypervisor, Virtualization, EndpointSecurity, NetworkExtension, `sandbox-exec`, and `pfctl`.
- These signals are evidence for diagnostics only; provider trust remains `None`, proof status remains `Missing`, and high-risk launch gates stay closed.

The current provider diagnostics slice exposed those probes through the CLI:

- `whoathere evidence providers` renders Linux/macOS provider proof status, unimplemented reason codes, mechanism/trust summaries, evidence counts, and read-only evidence signals.
- The command is diagnostic-only and does not invoke provider enforcement, package managers, registries, or OS mutation.

The current Linux readiness slice turned raw Linux probes into structured readiness diagnostics:

- `linux_containment_readiness_from_evidence` derives `required_primitives_present`, parsed no-new-privs/seccomp/userns/Landlock fields, and missing-primitive reason codes from read-only provider evidence.
- `whoathere evidence providers` now renders a `provider_readiness provider=linux` line so operators can see which primitives are missing before a real verifier exists.
- `proof_verification_enabled=false` is hard-coded in the readiness model until sandbox-owned verification proves same-subject containment and default-deny egress.
- Focused tests cover both fully populated synthetic evidence and real local fail-closed provider evidence.

The current macOS readiness slice added the same diagnostic contract for OS X endpoints:

- `macos_containment_readiness_from_evidence` derives VM isolation, egress-control, telemetry, framework/tool availability, beta-containment, and missing-verification reason codes from read-only provider evidence.
- `whoathere evidence providers` now renders a `provider_readiness provider=macos` line beside Linux readiness.
- macOS readiness remains explicitly beta and diagnostic-only; `proof_verification_enabled=false` remains mandatory until a VM/egress verifier can prove real same-subject controls.

The current machine-readable diagnostics slice added JSON output for automation:

- `whoathere evidence providers --json` renders schema-versioned Linux/macOS provider summaries, proof statuses, readiness objects, reason codes, and redacted evidence arrays.
- The default text output is unchanged for human diagnostics.
- JSON diagnostics do not change provider behavior; containment and egress remain `Missing` with trust `None`.

The verifier-plan contract slice added explicit future-verifier prerequisites:

- `LocalVerificationPlan` records platform, enforcement strategy, required checks, blocking reason codes, and whether verification can be attempted now.
- Linux and macOS plan builders derive from readiness models but keep `can_verify_now=false` while proof verification is unimplemented.
- `whoathere evidence providers --json` includes `verification_plan` objects so future provider-contract tests can assert exact missing controls without scraping text.

The provider readiness gate slice added CI-facing fail-closed checks:

- `whoathere evidence providers --json --require-ready` emits top-level `require_ready`, `provider_ready`, `status`, and `exit_code` fields.
- Until real Linux/macOS verifiers can produce `can_verify_now=true`, the command exits 20 with `status=fail_closed`.
- The default text and JSON diagnostics remain non-failing unless `--require-ready` is explicitly provided.

The Vault cache-key slice added promotion-time storage naming controls:

- `ArtifactRef::cache_object_key` validates digests and maps supported algorithms to `blobs/<algorithm>/<digest>` object keys.
- Admission refuses promotion for unsupported or path-unsafe digests and leaves artifacts unservable.
- Promoted `ServableGeneration` records now carry `cache_object_key`, and local-dev admission simulation renders it on successful promotion.

The current Vault cache lifecycle slice added inert cache state transitions:

- `whoathere-cache` provides an in-memory quarantine/promote store for inert bytes keyed by validated cache object keys.
- Empty payloads, invalid digests, unknown quarantine IDs, and duplicate promotions fail closed.
- Local-dev `/v1/cache-simulations` demonstrates quarantine-only and promote flows without serving package bytes or fetching registries.

The current cache hash-verification slice made quarantine content-addressed:

- `whoathere-cache` verifies SHA-256 payload bytes before quarantine and rejects digest mismatches.
- The internal SHA-256 implementation is pinned with the standard `abc` test vector.
- Unsupported verification algorithms, including current SHA-512 inputs, fail closed until implemented.
- Local-dev cache simulation now uses a real SHA-256 object key for inert fixture bytes.

The current promotion manifest slice added identity binding for promoted generations:

- `ServableGeneration` now records tenant id, request id, cache object key, evidence profile, policy version, and audit event id.
- `promotion_manifest()` returns a schema-versioned manifest view suitable for future object-store/audit persistence.
- Local-dev admission promotion output renders generation and audit identifiers alongside the cache object key.

The current manifest serialization slice made promotion metadata deterministic:

- `PromotionManifest::to_canonical_json()` renders stable field order with explicit escaping and no dependency changes.
- Admission tests pin manifest JSON and string escaping behavior.
- Local-dev admission promotion output now includes the nested canonical `promotion_manifest` object.

The current fetch-job schema slice added non-network fetch planning:

- `FetchJobRequest` and `FetchJobPlan` validate source URL, expected digest, byte limit, and cache object key before any fetcher exists.
- Valid metadata produces state `Planned` but always keeps `fetch_enabled=false`.
- Invalid digest, unsafe digest, zero byte limit, and non-HTTPS source metadata produce fail-closed rejected plans.
- Local-dev `/v1/fetch-job-simulations` exposes planned and rejected cases without network access.

The current fetch-result binding slice tightened promotion:

- `FetchJobResult` and `FetchResultBinding` carry tenant, admission request, artifact, digest, cache key, quarantine id, byte length/limit, network-attempt flags, and fetch audit metadata.
- Admission now requires a verified fetch-result binding before promotion; complete scan evidence alone returns `verified_fetch_result_missing`.
- Mismatched verified digest or cache object key returns `fetch_result_not_admission_ready` and does not promote.
- Promotion manifests include fetch job, quarantine, byte, and fetch audit metadata while still using inert local bytes only.

The current digest canonicalization slice removed placeholder digest promotion:

- Cache object keys now require canonical lowercase `sha256:<64 hex>` digests.
- Unsupported algorithms, short placeholder digests, uppercase/non-canonical hex, and path-like digest values fail closed before object keys are issued.
- Admission, CLI Vault simulation, registry fixtures, and local-dev routes now use real SHA-256 digest fixtures.
- SHA-512 remains an open gate until cache verification supports it end to end.

The current evidence binding slice tightened admission evidence:

- `EvidenceBundle::validate_for_profile` now requires profile id/version to match the selected evidence profile.
- Evidence results must be unique per job kind and must belong to the profile's requirement set.
- Admission fails closed with specific evidence reason codes before manual-review or auto-allow decisions.
- Local-dev admission simulation exposes profile-mismatch and duplicate-result denial paths.

The current admission identity slice tightened tenant/request isolation:

- Conflicting reuse of an admission request id with different metadata now fails closed with `admission_request_id_conflict`.
- Servable generation lookup now requires tenant id plus artifact identity.
- The same artifact can be promoted separately for different tenants without sharing the in-memory generation key.
- Existing local-dev and CLI simulations now use the explicit tenant-aware lookup.

The current registry rendering slice hardened future serving metadata:

- npm tarball URLs now percent-encode package-name and version path components.
- PyPI Simple links now percent-encode href path and fragment components while separately escaping visible HTML text.
- JSON rendering now escapes control characters, not only quote and backslash characters.
- This remains metadata-only; no package-serving route or package byte response was added.

The current cache lookup slice hardened future byte serving:

- `InMemoryCacheStore::promoted_bytes_for_artifact` requires both the artifact identity and cache object key to match.
- Wrong object keys, missing promoted objects, and artifact mismatches fail closed with distinct reason codes.
- Existing direct object-key byte lookup remains internal test support; future serving routes should use the exact artifact/key contract.
- This remains in-memory and inert; no tarball/file response route was added.

The current evidence subject slice bound scanner results to artifact identity:

- `EvidenceBundle` now carries the artifact digest and cache object key it describes.
- Admission compares evidence subject fields against the requested artifact before auto-allow or manual-review verdicts.
- Digest or cache-key subject mismatch fails closed before promotion.
- Local-dev admission simulation exposes the subject-mismatch denial path.

The current package-identity slice closed the local source-policy gap inside `protect`:

- `whoathere-source` discovers package identities from npm `package.json`, Python requirements files, and supported `pyproject.toml` dependency arrays, including PEP 517 build-system requirements.
- Identities carry ecosystem and source class (`PublicRegistry`, `DirectUrl`, `Git`, or `LocalPath`) so policy can deny dependency-confusion and direct-source risks before source scans or launch planning.
- `protect` filters workspace manifests by command ecosystem, adds argv identities for direct install commands, and writes redacted `protect-package-identity-gate` audit JSONL for blocked identities.
- The npm and pip package-identity fixture smokes both fail closed with `execution_reason=package_identity_policy_blocked` and no package-manager execution.

The current custom requirements slice closed a pip argv-file bypass:

- `pip install -r/-c` and `--requirement/--constraint` paths are collected from pip and `python -m pip` argv.
- Custom files are read only under `--workspace`; missing workspace fails closed with `requirements_argv_workspace_required`.
- Requirements identity and source scans now share recursive include handling for custom roots, including traversal, cycle, unreadable-file, and symlink escape denial.
- Custom requirements smokes prove internal packages deny at package identity and public package files with public index overrides deny at source scan.

The current evidence-job metadata slice bound scanner/detonator results to planned jobs:

- `EvidenceJobResult` now carries job id, job kind, state, canonical log digest, and reason codes.
- `EvidenceBundle::validate_for_profile` requires matching `EvidenceJobBinding` records for every result, bound to profile id/version, artifact digest, cache object key, and log digest.
- `whoathere-vault-api` can plan and bind metadata-only evidence jobs while keeping `execution_enabled=false` and rejecting execution, network, detonation, mismatch, invalid log digest, and failed-worker results.
- Local-dev `/v1/evidence-job-simulations` exposes valid and fail-closed binding paths without fetching packages, running scanners, detonating payloads, or storing raw logs.

The current static manifest job slice connected detector output to evidence-job binding:

- `whoathere-detector` now has a metadata-only `run_static_manifest_job` producer that reads inert manifest text, emits `StaticManifest` job state/reason codes, and computes a canonical `sha256:` digest over sanitized summary metadata.
- The npm scanner now parses supported JSON key paths, detects escaped lifecycle script keys under top-level `scripts`, covers broader install-adjacent lifecycle names, and fails closed on malformed package metadata.
- The PyPI scanner now fails closed on malformed supported `pyproject.toml` shape while keeping PEP 517 build-backend metadata suspicious but bindable.
- Local-dev `/v1/static-manifest-job-simulations` runs clean npm, malicious npm, PEP 517, empty, and unknown-selector paths through the existing evidence-job binder without execution, network, detonation, or raw log capture.

The previous implementation slice added containment launch planning and no-spawn gates:

- `whoathere-launch` builds explicit launch plans from tool, args, workspace, Vault origin, runtime dir, and containment/egress proof flags.
- Launch plans block missing Vault origin, invalid context, source-scan findings, argv registry/index overrides, missing egress proof, and missing containment proof before any install execution path.
- Runtime materialization creates private runtime/home/XDG dirs and `0600` generated npm/pip config, tracks cleanup-owned paths, and replaces placeholder paths in final env/argv when verified proof gates have already passed.
- Fake package-manager tests prove refused launch plans do not spawn a child process.
- `whoathere launch plan` exposes the gate state, and `protect --execute --workspace --vault-origin npm -- ci` now reports `launch_plan_blocked` before runner execution.
- Even when library tests construct verified proof objects, install workflows remain `execution_allowed=false` with `install_execution_not_enabled`.

The previous implementation slice added source scanning and sanitized launch-context planning:

- `whoathere-source` scans `.npmrc`, pip config, npm lockfiles, and requirements files with format-specific parsers and fail-closed findings for public registries, Unicode-escaped lockfile URLs, direct URLs, VCS sources, local paths, config indirection, URL credentials, env interpolation, unreadable includes, and invalid Vault origins.
- `protect --workspace --vault-origin` now runs source scans before runner planning. Unsafe source fixtures return exit 20 with `execution_reason=source_scan_blocked`; clean fixtures can plan context but still do not execute installs.
- npm and pip context planners clear ambient env, set Vault-only registry/index settings, list scrubbed env names/prefixes, and mark `launch_context_execution_enabled=false`.
- Redaction now covers npm/pip auth markers, split sensitive argv values, proxy credentials, URL credentials, and common cloud token markers; safe env key names remain visible.
- Readonly child execution now requires `--execute` plus an absolute package-manager path and runs with `env_clear`; relative `npm --version` execution through PATH/shims is refused.
- Source fixtures were added under `whoathere/tests/fixtures/source-clean` and `whoathere/tests/fixtures/source-overrides`.

The second implementation slice addressed reviewer findings before expanding scope:

- Deny decisions now become real process exit codes through `evaluate_command` and `main`.
- Generated shims use the current executable path, single-quote shell quoting, and create-new writes that refuse existing files.
- `protect --policy` loads policy before any execution plan; invalid/unreadable/unknown-schema policy fails closed.
- Config and policy parsers reject unknown `schema_version` values.
- Readonly `--version` probes are a distinct low-risk command class; install/build/import execution remains gated.
- `AllowVaultOnly` no longer allows arbitrary loopback; exact configured Vault egress is modeled separately.
- Admission decisions for unknown request IDs fail closed instead of panicking.
- `whoathere-vault-dev` exposes only local-dev control/simulation routes and no package-serving routes.

## Completion Audit

| Requirement | Evidence | Status |
| --- | --- | --- |
| Run 3-5 review/improve/validate loops | Five initial pass files, `quality-loop-summary.md`, and slice-level pass evidence in `slice-handoff-ledger.md`. | Complete for completed slices |
| Build from granular plans | Implemented local CLI/core/policy/audit/sandbox/evidence/detector/admission/registry/runner/source/launch slices. | MVP-safe slices complete |
| Document orchestration in one morning-readable file | This report. | Complete |
| Do not block | Used local deterministic work; skipped credential/network AI review. | Complete |
| Stay sandboxed | Product code stayed under `/Users/jdc/src/whoathere/whoathere`; docs under `docs/product-build-run`; shim materialization only under `/private/tmp/whoathere-shims-smoke-codex`. | Complete |
| Do not use real malware | No actual malware or package lifecycle execution; fixtures are inert and only read as text. | Complete |
| Working software that controls risk | CLI, config/policy checks, source policy check, package-identity protect gate, source-file scan gate, sanitized launch-context planning, deterministic SHA-256 launch/source fingerprints, typed challenge-subject same-session fresh proof-gated launch planning, launch/protect audit JSONL, cleanup manifest reporting/execution, guarded cleanup for launch-owned temp runtime paths, private runtime materialization behind verified proof objects, fake package-manager no-spawn tests, static scan, metadata-only static manifest job binding, in-memory immutable sanitized job-log receipts, evidence profiles, metadata-only fetch/evidence job binding, fail-closed admission simulation, local-dev HTTP router, safe wrapper planning, and shim materialization all compile and pass tests. | MVP-safe slices complete |
| Full deployable WhoaThere system | OS sandboxing, real registry proxy, cloud deployment, persistence, dynamic detonation, and production auth/audit are not implemented. | Not complete |

I am not marking the full thread goal complete because the requested end state is broader than this MVP-safe build. The current result is a tested local MVP foundation with source scanning, launch-context planning, and containment launch planning that can be picked up for the next real containment/egress proof slice.

## Resume Prompt

```text
Continue WhoaThere from /Users/jdc/src/whoathere.

Read first:
- docs/product-build-run/morning-orchestration-report.md
- docs/product-build-run/slice-handoff-ledger.md
- whoathere/README.md

Objective:
Implement the next MVP-safe slice toward protected npm/pip installs: begin the fake-provider integration harness for Linux/macOS proof-provider spikes, keeping it unable to invoke real package installs. Do not run package installs or malware. Preserve fail-closed behavior, keep cleanup explicit, and keep real install execution disabled until verified providers are tested and reviewed.

Required gates:
- cargo fmt --manifest-path whoathere/Cargo.toml --all --check
- cargo test --manifest-path whoathere/Cargo.toml
- cargo clippy --manifest-path whoathere/Cargo.toml --workspace --all-targets -- -D warnings
- Update docs/product-build-run/slice-handoff-ledger.md
- Update docs/product-build-run/morning-orchestration-report.md
```
