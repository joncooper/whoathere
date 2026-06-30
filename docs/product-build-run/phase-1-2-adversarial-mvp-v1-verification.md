# WhoaThere Phase 1/2 Adversarial MVP v1 Verification

## Scope

This checkpoint records an adversarial verification pass for the completed Phase 1 and Phase 2 local endpoint work. The pass assessed the MVP v1 standards before applying them, then verified the current implementation against the updated standards.

Phase order:

1. Phase 1 local CLI MVP.
2. Phase 2 local isolation/proof-provider hardening.

Phase 3 Vault deployment, Phase 4 detonation automation, and Windows endpoint support remain out of scope.

## Phase 1 Standard Assessment

The initial Phase 1 standard was necessary and mostly sufficient. Two clarifications were required before applying it:

- `npx` and `npm exec` are in scope for interception and fail-closed reporting, not for safe transient package execution.
- Phase 1 must explicitly prove that it does not execute install/build/import paths, mutate PATH automatically, fetch public registries, or treat registry/index steering as an egress boundary.

No requirement was relaxed because of implementation status. No perfectionist requirement was added.

## Final Phase 1 MVP v1 Standard Used

Phase 1 is a credible MVP v1 only if all of the following are true:

- The local CLI command surface needed for the MVP works with stable exit codes and fail-closed defaults.
- Default PATH shims cover `npm`, `npx`, `pip`, and `pip3`; `python` and `python3` shims are explicit opt-in only.
- Shim materialization is explicit, refuses unsafe overwrite cases, quotes paths safely, and does not mutate the user's shell or PATH automatically.
- `npm install`, `npm ci`, `npx`, `npm exec`, `pip install`, `pip3 install`, and `python -m pip install` are classified and routed through `protect` behavior.
- `npx` and `npm exec` are intercepted and denied/reported as high-risk transient execution unless a later verified containment path exists.
- `protect` gates package identity, dependency-confusion policy, source scanning, launch planning, and audit writes before any package-manager execution.
- High-risk install/build/import execution remains blocked, including clean npm/pip workspaces.
- Readonly version probes are the only execution shape Phase 1 can allow, and only through the guarded runner path with explicit execution and absolute binary requirements.
- Source override checks cover claimed `.npmrc`, pip config, npm lockfile, requirements, custom `-r`/`-c` files, traversal, symlink escapes, and direct/git/local dependency cases.
- Static manifest scanning detects npm lifecycle scripts and PyPI PEP 517 metadata without executing them; PyPI PEP 517 metadata is suspicious metadata, not an automatic Phase 1 deny by itself.
- Audit and diagnostic output redacts secrets, raw nonces, raw proof material, raw evidence, local replay-store paths, and package bytes.
- Local-dev Vault/registry/scanner routes remain simulations only and do not fetch public registries, execute scanners, detonate packages, or serve real package archives.
- Docs accurately state implemented behavior, safety limits, and Phase 2+ deferrals.

## Phase 1 Verification Result

Verdict: pass. No Phase 1 implementation fix was required.

Focused tests and probes:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-core -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli protect -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli shim -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-source -p whoathere-policy -p whoathere-detector -p whoathere-runner -- --nocapture
scripts/whoathere-endpoint-smoke.sh
cargo run --quiet --manifest-path whoathere/Cargo.toml -p whoathere-cli -- scan manifest npm-package-json whoathere/tests/fixtures/npm/postinstall-exfil/package.json
cargo run --quiet --manifest-path whoathere/Cargo.toml -p whoathere-cli -- scan manifest pyproject whoathere/tests/fixtures/pypi/pep517-backend/pyproject.toml
cargo run --quiet --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 npm -- ci
cargo run --quiet --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 pip -- install fixture
cargo run --quiet --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect npx -- left-pad
cargo run --quiet --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect npm -- exec left-pad
cargo run --quiet --manifest-path whoathere/Cargo.toml -p whoathere-cli -- protect --execute --workspace whoathere/tests/fixtures/custom-requirements --vault-origin http://127.0.0.1:4873 python -- -m pip install -r custom-requirements.txt
```

Observed evidence:

- Phase 1 focused unit tests passed.
- Endpoint smoke installed four default shims and proved `npm ci` plus `pip install` are intercepted and denied before package-manager execution.
- npm `postinstall` fixture was detected with `npm_lifecycle_postinstall`.
- PyPI PEP 517 fixture was detected with `pypi_pep517_build_backend` without backend execution.
- Clean `npm ci`, clean `pip install`, and `python -m pip install` reached launch planning and failed closed because verified egress/containment proofs were missing.
- `npx` and `npm exec` were classified as high-risk transient execution and denied/reported without execution.

## Phase 2 Standard Assessment

The initial Phase 2 standard was necessary and mostly sufficient. Three clarifications were required before applying it:

- Provider readiness may report host capabilities, but readiness diagnostics must never be promoted into production proof.
- Linux active-probe fixture/admission success is an evidence-contract check only; it must not mint trusted launch proofs or authorize package-manager execution.
- Docker active-probe support is useful diagnostic coverage but not required as a production containment guarantee for MVP v1, because production proof mapping remains deferred.

No requirement was relaxed because of implementation status. No perfectionist requirement was added.

## Final Phase 2 MVP v1 Standard Used

Phase 2 is a credible MVP v1 only if all of the following are true:

- Provider readiness explicitly distinguishes `diagnostic_only`, `partial`, `beta`, and `verified` control levels.
- macOS remains the first endpoint priority and is clearly labeled beta/limited unless real VM, egress, telemetry, and proof verification are implemented.
- Linux remains the second endpoint priority and is clearly labeled as readiness/proof-contract work unless a real runner and proof mapper exist.
- Read-only diagnostics, beta readiness, operator assertions, CLI flags, registry/index steering, active-probe receipts, and test-only providers cannot authorize production high-risk execution.
- `evidence providers --json --require-ready` fails closed until real providers can verify high-risk execution readiness.
- High-risk npm/pip execution remains fail-closed unless containment and Vault-only egress proofs are both verified for the exact launch subject/context.
- Proof checks bind subject, context hash, configured Vault host, provider identity/session, freshness, and challenge/replay state.
- Launch gates reject missing, stale, wrong-subject, wrong-context, wrong-Vault, mismatched-provider-session, diagnostic-only, and operator-asserted proofs before runtime materialization.
- Active-probe receipt/admission code rejects missing, mutated, overpermissive, stale/replayed, wrong-subject, wrong-context, and wrong-Vault evidence, while still not minting production proofs.
- The test-only provider harness can exercise success paths but cannot enable real install execution.
- Docs accurately state what is implemented, what is diagnostic/beta, what remains fail-closed, and what is deferred to Phase 3+.

## Phase 2 Verification Result

Verdict: pass. No Phase 2 implementation fix was required.

Focused tests and probes:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-sandbox readiness -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-sandbox active_probe -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-launch -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli evidence_providers -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml operator -- --nocapture
scripts/whoathere-provider-smoke.sh
scripts/whoathere-provider-challenge-smoke.sh
scripts/whoathere-linux-active-probe-fixture-smoke.sh
scripts/whoathere-linux-active-probe-admission-smoke.sh
```

Observed evidence:

- macOS provider diagnostics reported `provider_ready=false`, `status=fail_closed`, `proof_verification_enabled=false`, and `can_verify_now=false`.
- Provider challenge smoke generated a challenge-bound probe manifest and failed closed without containment or egress proof satisfaction.
- Linux active-probe fixture smoke accepted the complete fixture as a receipt only, while reporting `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
- Linux active-probe admission smoke accepted only replay-owned complete receipts and rejected replayed, unknown, mutated, and incomplete receipts.
- Launch tests covered stale proof, wrong context, wrong Vault, wrong subject, mismatched provider session, operator assertion, missing egress, and test-only success-path boundaries.

## Remaining Deferred Work

The following are not required for Phase 1/2 MVP v1 and remain deferred:

- Production macOS VM helper and packet-filter or NetworkExtension enforcement.
- Production Linux namespace/seccomp/cgroup/Landlock runner and packet-filter enforcement.
- Mapping real provider receipts into trusted production launch proofs.
- Production Vault deployment, authenticated proxying, durable cache, public package fetch, and tenant-aware control plane.
- Dynamic detonation workers and behavior analysis automation.
