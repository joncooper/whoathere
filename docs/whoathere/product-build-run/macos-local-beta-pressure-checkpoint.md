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
- Added `scripts/whoathere-real-project-compatibility.sh` for repeatable package-risk assessment
  against existing local npm, pip, and uv projects without host package execution.
- Calibrated uv lockfile handling after real-project testing. Normal registry package entries with
  wheel or sdist artifact URLs are now recorded as registry lockfile evidence, not denied as direct
  URL dependencies. VCS, local, editable, direct URL, native, and binary classes remain
  conservative.

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
- `scripts/whoathere-real-project-compatibility.sh /Users/jdc/src/CodexBar:npm /Users/jdc/src/monoscope:npm /Users/jdc/src/halp-me-resume:auto /Users/jdc/src/autoport:uv /Users/jdc/src/ramp-monorepo/ledger:uv`
- ASCII scan over docs, scripts, and Rust sources

## Real Project Compatibility Pass

The compatibility harness was run against five local projects that were not synthetic attack
fixtures:

| Project | Ecosystem | Packages assessed | Verdict | Elapsed |
| --- | --- | ---: | --- | ---: |
| `/Users/jdc/src/CodexBar` | npm | 1 | manual_review | 0s |
| `/Users/jdc/src/monoscope` | npm | 931 | manual_review | 2s |
| `/Users/jdc/src/halp-me-resume` | auto | 106 | manual_review | 1s |
| `/Users/jdc/src/autoport` | uv | 17 | manual_review | 11s |
| `/Users/jdc/src/ramp-monorepo/ledger` | uv | 2 | manual_review | 0s |

External scanners were intentionally skipped in this first compatibility run so the package-risk
classifier could be measured by itself. The observed results were conservative rather than
permissive: missing baselines, missing scanner receipts, missing publish-age metadata, and missing
reputation metadata keep packages in manual review. This is expected for a fresh local beta state
with no approved history.

The pass found one useful false-positive class: uv lockfiles include normal registry package
records with `sdist` and `wheels` artifact URLs. Those should not be treated as direct URL
dependencies. The classifier now reads the package source line instead of the entire lockfile block
when deciding whether a package came from a registry, direct URL, VCS, local path, or editable
source. Workspace root editable entries such as `source = { editable = "." }` are ignored because
the root project is assessed separately from its dependencies.

Remaining real-project friction is deliberate for the beta:

- Fresh state without approved package history requires manual review.
- Scanner receipts are useful evidence but are not allowed to authorize sync-back by themselves.
- Registry lockfile records are visible in the output, but VCS, local, editable, direct URL,
  native, binary, and unknown package classes remain blocked or manual review by default.

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
- Decide whether Python API-compatible malicious behavior needs an additional project-mode method
  call probe beyond the existing import probes and fixture-mode API canary coverage.
- Run real-project compatibility again with external scanners enabled after scanner bootstrap is
  available in the current environment, then compare scanner friction against package-risk-only
  friction.
