# macOS Local Beta Pressure Checkpoint

Date: 2026-06-29

## Scope

This checkpoint covers the current macOS local beta pressure pass. It focuses on command-line
security behavior, not installer, GUI, packaging polish, or enterprise Vault work.

## Completed In This Pass

- Added clearer scanner receipts: `decision_summary`, `host_effect`, and `recommended_actions`
  now explain what scanner output means and whether it can be used as evidence.
- Added explicit npm transitive lockfile risk handling. `package-lock.json` and
  `npm-shrinkwrap.json` package entries now become package-risk subjects, so lockfile-only
  second-stage packages are visible. Non-registry lockfile sources are denied by default.
- Added uv lockfile visibility. `uv.lock` entries now become package-risk subjects, and source
  scanning now inspects `uv.lock` and `poetry.lock` for external, VCS, local, and interpolated
  sources.
- Expanded pressure harnesses for realistic local npm, pip, and uv project shapes, including
  maintainer-update diffs, npm lockfile poisoning, uv lockfile VCS/local sources, static
  API-compatible malicious behavior, delayed CI activation, platform-specific code, and
  native/binary markers.
- Added an opt-in VM pressure gate to `scripts/whoathere-local-beta-pressure-suite.sh`.
  By default it is skipped; when `WHOATHERE_PRESSURE_ENABLE_VM=1` and
  `WHOATHERE_PRESSURE_RUNTIME_ARCHIVE` are set, it runs same-host runtime qualification, including
  live VM detonation and clean sync-back/malicious no-sync validation.

## Validation Passed

- `cargo test --manifest-path whoathere/Cargo.toml`
- `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`
- `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`
- `scripts/whoathere-scanner-integration-smoke.sh`
- `scripts/whoathere-package-risk-smoke.sh`
- `scripts/whoathere-real-world-attack-harness.sh`
- `scripts/whoathere-local-beta-pressure-smoke.sh`
- `scripts/whoathere-local-beta-pressure-suite.sh` with loopback compatibility enabled
- `WHOATHERE_PRESSURE_SKIP_COMPAT=1 scripts/whoathere-local-beta-pressure-suite.sh`
- ASCII scan over docs, scripts, and Rust sources

## Current Security Posture

The beta is meaningfully stronger for local development than raw `npm`, `pip`, or `uv` because
high-risk package execution stays out of the host, scanner and package-risk evidence is explicit,
fresh and unpinned packages are conservative, risky package classes do not auto-sync, and suspicious
lockfile or source changes are visible before copy-back.

The beta still should not be described as comprehensive package safety. It does not prove arbitrary
packages safe, does not solve runtime application protection, and does not auto-sync native,
binary, VCS, direct URL, editable, or unknown artifacts.

## Remaining Work Before Declaring This Goal Complete

- Run the opt-in VM pressure suite against a current signed preview archive:
  `WHOATHERE_PRESSURE_ENABLE_VM=1 WHOATHERE_PRESSURE_RUNTIME_ARCHIVE=<archive> scripts/whoathere-local-beta-pressure-suite.sh`.
- Run against several real external npm, pip, and uv projects that are not synthetic fixtures, then
  record observed false positives, false negatives, elapsed time, and workflow friction.
- Decide whether Python API-compatible malicious behavior needs an additional project-mode method
  call probe beyond the existing import probes and fixture-mode API canary coverage.
- Tune any noisy package-risk results found by real-project testing without relaxing fail-closed
  behavior for high-risk package execution or sync-back.
