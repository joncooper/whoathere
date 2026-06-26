# WhoaThere Implementation Workspace

This directory is the scoped implementation workspace for the WhoaThere supply-chain security product. It is intentionally separate from the existing Swift timer app at the repository root.

The current Phase 1 cutline is documented in `docs/whoathere/product-build-run/phase-1-mvp-checkpoint.md`: macOS endpoint behavior first, Linux second, Windows deferred, and high-risk package-manager execution still fail-closed until Phase 2 proves real containment and Vault-only egress.

The current Phase 2 isolation cutline is documented in `docs/whoathere/product-build-run/phase-2-isolation-checkpoint.md`: local provider diagnostics now classify `diagnostic_only`, `partial`, `beta`, and `verified` control levels, while high-risk npm/pip execution remains fail-closed until real same-subject containment and Vault-only egress proofs exist.

The current Phase 3 Vault cutline is documented in `docs/whoathere/product-build-run/phase-3-enterprise-vault-checkpoint.md`: the Vault MVP has a bounded local HTTP data plane, npm/PyPI promoted-cache compatibility routes, fail-closed readiness, enterprise auth/bind boundary validation, tenant-aware route checks, and an AWS-first deployment skeleton. Durable production storage, upstream fetch, scanner execution, and full ECS/Aurora deployment remain gated.

## Current Scope

Local MVP-safe slices:

- CLI command surface for `doctor`, `status`, `config check`, `policy check`, `protect`, dry-run shim manifests, static manifest scans, launch/protect audit JSONL, evidence profile listing, in-memory Vault admission simulation, one-shot local-dev HTTP request simulation with validated synthetic headers, and bounded loopback-only local-dev Vault server.
- Config, policy, audit, endpoint event, command classification, and stable exit-code primitives.
- Dependency-confusion source policy evaluator.
- Local policy parser with schema-version rejection.
- Package-identity discovery for npm `package.json`, Python requirements/constraint files including custom `pip -r/-c` argv roots, and supported `pyproject.toml` dependency arrays; `protect` gates internal namespace dependency-confusion and direct/git/local dependency sources before source scans or launch planning.
- Sandbox backend trait, containment labels, typed containment/egress proof objects, challenge-first proof provider SPI, nonce/expiry-bound provider verification challenges with an in-memory single-use replay guard, expanded Vault-only egress probe matrix covering public registries, metadata/link-local, loopback, private IPv4, IPv6, and public DNS destinations, fail-closed Linux/macOS provider skeletons with read-only capability probes, Linux/macOS containment readiness diagnostics, test-only fake provider harness, proof subject/provenance/freshness/context/session summaries, default-deny-attested Vault-only egress decision model, and cleanup lease model.
- Guarded runner that refuses install/build/import execution and permits only explicit readonly version probes.
- Source-file scanner for `.npmrc`, pip config, npm lockfiles, and requirements files; `protect --workspace --vault-origin` gates unsafe sources before execution planning.
- Custom pip requirements/constraint files referenced by argv are inspected within the configured workspace for both package identity and source overrides; missing workspace, traversal, unreadable files, cycles, and symlink escapes fail closed.
- Sanitized npm/pip launch context planner that clears ambient env, points registry/index settings only at an explicit Vault origin, and records that independent egress enforcement is still required.
- Containment launch-plan layer that requires challenge-subject, same-session, fresh, SHA-256 launch-context-bound verified egress and containment proof before private runtime config materialization, emits deterministic SHA-256 launch/source fingerprints, tracks cleanup-owned paths and cleanup manifests, and still keeps install execution disabled.
- Guarded cleanup reporting/execution for launch-owned temp runtime paths, refusing non-WhoaThere temp roots, parent-directory escapes, and paths outside the runtime root.
- Launch audit JSONL records with proof summaries, launch/source fingerprints, redaction, and cleanup summaries; `protect --audit-path` can append source-scan and launch-gate deny records without executing package managers.
- Evidence profiles for npm/PyPI artifact classes.
- Provider diagnostics that render text or JSON read-only local evidence, Linux/macOS readiness reasons, and verifier prerequisite plans without enabling proof verification.
- Fail-closed provider readiness check mode for CI via `evidence providers --json --require-ready`.
- Static manifest detector for npm lifecycle scripts and PyPI PEP 517 metadata.
- Metadata-only static manifest job producer that parses npm `package.json` lifecycle keys including escaped forms, performs conservative PyPI `pyproject.toml` shape validation, emits sanitized reason-code/log-digest summaries, and binds through the Vault evidence-job contract without execution or raw log capture.
- In-memory immutable sanitized job-log store that appends detector summaries by job id, verifies `sha256:` log digests, parses summary fields back to job identity, rejects raw log capture, and rejects same-job rewrites.
- In-memory Vault admission model that promotes only after profile-bound unique mandatory evidence is complete for the same artifact digest/cache key and a verified fetch-result binding matches tenant, request, artifact, digest, cache key, quarantine id, and byte limit.
- Tenant-aware Vault admission records that reject conflicting request-id reuse and keep promoted generations scoped by tenant plus artifact.
- Deterministic promotion manifest JSON binding generation, tenant/request identity, artifact identity, cache object key, fetch job/quarantine metadata, policy, evidence profile, and audit event id.
- In-memory Vault cache store that hash-verifies inert bytes, quarantines them, promotes them only by canonical lowercase `sha256:<64 hex>` content-addressed object key, and exposes exact artifact-plus-key lookup for future serving paths.
- Vault fetch-job planning schema that validates source URL, expected digest, byte limit, and canonical cache object key while keeping network fetch disabled.
- Vault evidence-job planning and result-binding schema that ties static/dynamic scanner result metadata to job id, evidence profile, artifact digest, cache object key, canonical log digest, and audit event id while keeping execution, network, and detonation disabled.
- Local-dev Vault HTTP router/server for health, fail-closed protected-traffic readiness, evidence profiles, admission simulation, inert cache lifecycle simulation, metadata-only static manifest jobs, sanitized job-log receipt simulation, promoted-only registry metadata simulations, exact-match inert promoted cache-byte simulation routes, package-byte `HEAD` support, single byte-range support, conditional ETag handling, immutable cache validator/security headers, sanitized per-request server summaries, and binary-safe response bodies for future package archives.
- Enterprise Vault boundary primitives for non-loopback/auth posture validation and protected-route bearer-token checks when enterprise HTTP options are used.
- Registry facade helpers and local-dev simulation routes that render only promoted generations, percent-encode URL components, escape display text, avoid public registry URLs, fail closed for unpromoted artifacts, and serve only fixed inert bytes through exact artifact-plus-cache-key lookup.
- Inert fixture scaffolding for malicious-package test shapes.

Default materialized shims cover `npm`, `npx`, `pip`, and `pip3`. `python` and `python3` shim handling is classified and listed as optional because default Python interception would break ordinary Python tooling; materialization requires explicit `shim install --include-python --dest <sandbox-dir>` opt-in.

Still gated:

- Real package-manager execution.
- Install/build/import package-manager execution.
- Treating registry/index steering as an egress security boundary.
- Treating launch planning as permission to execute installs.
- PATH mutation.
- Linux namespace/seccomp/Landlock runner.
- macOS VM helper.
- Production Vault service persistence/full AWS deployment and public registry fetch.
- Dynamic detonation of install/build/import paths.
- Real scanner/detonator worker execution and durable production job-log storage/signing.
- Verified OS containment and network egress enforcement providers; the production providers must implement the challenge-first SPI with trusted clock/replay controls before satisfying high-risk install gates. CLI assertion flags are diagnostic only and do not satisfy high-risk install gates. Test-only verified proof helpers are behind the non-default `whoathere-sandbox/test-support` feature.

## Run

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- doctor
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- status
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- config check whoathere/examples/whoathere.config
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- policy check whoathere/examples/whoathere.policy
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- policy check-source @company/build-tools public --internal-prefix @company/
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- policy check-source @company/build-tools public --policy whoathere/examples/whoathere.policy
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- shim install --dry-run
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- shim install --dry-run --include-python
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- shim install --dest /private/tmp/whoathere-shims --include-python
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect npm -- --version
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --policy whoathere/examples/whoathere.policy npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --policy whoathere/tests/fixtures/package-identity/whoathere.policy --workspace whoathere/tests/fixtures/package-identity npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --policy whoathere/tests/fixtures/package-identity/whoathere.policy --workspace whoathere/tests/fixtures/package-identity pip -- install -r requirements.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --policy whoathere/tests/fixtures/custom-requirements/whoathere.policy --workspace whoathere/tests/fixtures/custom-requirements pip -- install -r custom-requirements.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --workspace whoathere/tests/fixtures/custom-requirements --vault-origin http://127.0.0.1:4873 pip -- install --requirement=source-override.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- source scan-workspace whoathere/tests/fixtures/source-overrides --vault-origin http://127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- source context npm --vault-origin http://127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --workspace whoathere/tests/fixtures/source-overrides --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch plan --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch audit --audit-path /private/tmp/whoathere-launch-audit.jsonl --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --audit-path /private/tmp/whoathere-protect-audit.jsonl --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
# When a WhoaThere runtime cleanup manifest exists:
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch cleanup --manifest /private/tmp/whoathere-runtime/.whoathere-cleanup.manifest
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- scan manifest npm-package-json whoathere/tests/fixtures/npm/postinstall-exfil/package.json
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- scan manifest pyproject whoathere/tests/fixtures/pypi/pep517-backend/pyproject.toml
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence profiles
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --json
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --json --require-ready
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault simulate
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault simulate --complete
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
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/npm/tarballs/fixture/1.0.0 --header 'If-None-Match: "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f"'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http HEAD /v1/registry-simulations/npm/tarballs/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET '/v1/registry-simulations/npm/tarballs/fixture/1.0.0?cache_key_mismatch=true'
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http HEAD /v1/registry-simulations/pypi/files/pypi/fixture/1.0.0
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-serve --bind 127.0.0.1:48731 --max-requests 1 --idle-timeout-ms 10000
# With the bounded server running:
curl -fsS -i -H 'Range: bytes=6-10' http://127.0.0.1:48731/v1/registry-simulations/npm/tarballs/fixture/1.0.0
```

## Safety

The local MVP does not execute package-manager installs, mutate PATH, run lifecycle scripts, invoke Python build backends, import packages, run Node scripts, fetch public registries, run scanner/detonator workers, serve unvetted package archives, or execute malware. Fixture tests read inert metadata/config files and local-dev registry file routes serve only fixed inert bytes or deterministic safe fixture archives through exact promoted cache lookup. The local-dev server binds only to loopback, is bounded by `--max-requests`, and exits on `--idle-timeout-ms`; non-loopback local-dev binds fail closed. `/healthz` reports liveness, while `/readyz` fails closed for protected traffic until real dependencies are verified. Enterprise/non-loopback serving requires explicit auth configuration and protected-route bearer-token validation before use. `protect` returns nonzero for denied install paths, blocks active namespace/direct-source identity findings before source scans or launch planning, and can append redacted audit JSONL for deny decisions. Evidence-job and static-manifest-job simulations validate metadata bindings only and reject execution, network, detonation attempts, raw log capture, and unknown fixture selectors. Static-manifest job logs are sanitized summaries only, stored in an in-memory append-only simulation, and rejected if the digest, schema, identity fields, raw-log flag, or same-job immutability check fails. Registry simulations render promoted metadata only, serve fixed inert bytes only for the exact promoted artifact/key pair, return `HEAD` metadata without body bytes, support single byte ranges, and fail closed for unpromoted artifacts, tenant mismatches, cache-key mismatches, malformed ranges, unsupported range units, multiple ranges, or unsatisfiable ranges. `launch cleanup` is report-only unless `--execute` is passed and only follows WhoaThere cleanup manifests under safe temp runtime roots. Readonly version probes require explicit `--execute` and an absolute package-manager binary path before spawning a child process.

`vault dev-http --header` is for local simulation only. It rejects malformed headers, line-break injection, and simulator-owned `Host`/`Content-Length` headers before routing. Local-dev server request summaries are sanitized: they record method, route kind, status code, range state, declared response length, and wire response-body byte count, but they do not log request bodies, response bodies, authorization headers, registry tokens, package bytes, or full target URLs.
