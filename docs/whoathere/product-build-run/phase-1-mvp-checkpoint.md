# WhoaThere Phase 1 MVP Checkpoint

## Scope

Phase 1 is the secure local CLI MVP. It is intentionally not a 1.0 system and not a package execution sandbox.

The Phase 1 priority order is:

1. macOS endpoint behavior first.
2. Linux endpoint and CI behavior second.
3. Windows deferred.

## Phase 1 Behavior

The Phase 1 CLI provides:

- PATH shim materialization for `npm`, `npx`, `pip`, and `pip3`.
- Optional `python` and `python3` shims only with explicit `--include-python`.
- `endpoint setup` guidance that prints fail-closed shell exports and provider readiness checks without mutating the user's shell.
- `protect` gates for npm and pip workflows, including `npm install`, `npm ci`, `npx`/`npm exec`, `pip install`, and `python -m pip` command classification.
- Source and policy gates for dependency confusion, direct/git/local package sources, npm registry overrides, pip index/extra-index overrides, custom requirements/constraint files, and invalid Vault origins.
- Redacted audit JSONL for package-identity, source-scan, launch-plan, replay-store, and challenge-authority deny/diagnostic paths.
- Local-dev safe fixture and route simulations for validating compatibility without public package fetches or untrusted execution.

## Security Posture

Phase 1 remains fail closed for high-risk package-manager execution.

Allowed execution is limited to explicitly requested readonly version probes with absolute package-manager paths. npm lifecycle scripts, Python build backends, Python import-time payloads, package installs, scanner workers, detonation workers, public registry fetches, and OS/network mutation are not executed by Phase 1.

Registry/index steering is treated as compatibility planning, not as an egress security boundary. A future Phase 2 provider must prove actual containment and Vault-only egress before any high-risk install can be allowed.

## Exit Criteria Evidence

| Exit criterion | Evidence |
| --- | --- |
| macOS-first, Linux-second CLI MVP behavior is clear and documented | This checkpoint plus the priority note in `morning-orchestration-report.md`; provider diagnostics cover macOS/current-host and Linux scopes while Windows remains deferred. |
| npm/pip PATH shims work for protected workflows in local tests | `scripts/whoathere-endpoint-smoke.sh` materializes shims, verifies `command -v npm` and `command -v pip` resolve to WhoaThere shims, and confirms `npm ci` plus `pip install fixture` are intercepted and denied before package-manager execution. |
| protect/source/policy gates block dependency confusion, direct URLs, source overrides, extra indexes, and high-risk install execution | CLI/source/policy unit tests cover internal namespace dependency confusion, direct/git/local source denial, npm registry overrides, pip extra-index/index overrides, custom requirements/constraints, and invalid Vault origins. |
| high-risk package-manager execution remains fail-closed unless explicitly supported by Phase 1 | `protect_clean_workspace_plans_vault_context_but_keeps_install_gated`, `protect_pip_install_remains_fail_closed_after_source_gate`, and endpoint smoke assert npm/pip installs return deny status until verified containment and egress proofs exist. |
| audit records are redacted and useful for denied workflows | CLI audit tests cover package-identity, source-scan, launch-plan, cleanup, replay-store, and challenge-authority summaries without raw secrets, raw nonces, raw evidence, or local store paths. |
| focused tests and one final full validation pass are green | Phase 1 closeout focused tests passed for the pip high-risk fail-closed regression, endpoint shim smoke, and source/policy gates. The final full validation pass is recorded in `morning-orchestration-report.md`. |
| docs state what Phase 1 does, does not do, and what remains for Phase 2 | This checkpoint and `whoathere/README.md` list the implemented Phase 1 behavior and gated work. |

## Deferred To Phase 2

- Real macOS containment provider.
- Real Linux containment provider.
- Verified Vault-only egress provider.
- Real package-manager install/build/import execution under containment.
- Production-quality provider challenge collection and proof mapping.

## Deferred To Phase 3

- Production Vault service deployment.
- Authenticated tenant-aware package proxy.
- Durable package cache, metadata store, queue/workflow orchestration, and production audit sink.
- Real upstream npm/PyPI fetch path.

## Deferred To Phase 4

- Dynamic detonation workers.
- Behavior analysis automation.
- Admin workflows beyond local-dev audit and diagnostic records.

## Phase 1 Closeout Validation

Focused checks:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli protect_pip_install_remains_fail_closed_after_source_gate -- --nocapture
scripts/whoathere-endpoint-smoke.sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-source -p whoathere-policy
```

Final validation:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
rg -n "[^[:ascii:]]" README.md docs/whoathere/product-build-run scripts whoathere/README.md whoathere/Cargo.toml whoathere/Cargo.lock whoathere/crates whoathere/examples whoathere/tests whoathere/probe-images
```

Result: all checks passed. Full workspace tests passed with 367 unit tests plus doctests.
