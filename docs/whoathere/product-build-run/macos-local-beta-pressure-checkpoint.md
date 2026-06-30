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
- Tightened command-entry package policy. npm `bin` entries and Python console-script entry points
  now force manual review because they create post-install execution surfaces that the local beta
  does not claim to protect at normal runtime.
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
- Added a project-mode Python API-use probe for VM detonation. When WhoaThere can infer a safe
  import module for a pip or uv local project, the guest now imports it and exercises a small set of
  common zero-argument module functions and client methods inside the VM. Canary or network markers
  still deny sync-back. This improves coverage for API-compatible malicious packages without
  claiming full runtime behavior protection.
- Added `docs/whoathere/product-build-run/macos-local-beta-cli-guide.md`, a short CLI-only guide for
  building, checking VM readiness, running scanners and package-risk assessment, detonating npm,
  pip, and uv workflows, interpreting decisions, and recovering from blocked cases.

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
- `whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-project-payload.sh`
- `swift test` in `whoathere/helpers/macos-vm-helper`
- `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli vm_detonate -- --nocapture`
- `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli scanners_run -- --nocapture`
- `cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli package_risk -- --nocapture`
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

The same project set was then run with external scanners enabled:

| Project | Ecosystem | Scanner ecosystem | Packages assessed | Verdict | Scanner clean | Elapsed |
| --- | --- | --- | ---: | --- | --- | ---: |
| `/Users/jdc/src/CodexBar` | npm | npm | 1 | manual_review | false | 41s |
| `/Users/jdc/src/monoscope` | npm | npm | 931 | manual_review | false | 140s |
| `/Users/jdc/src/halp-me-resume` | auto | auto | 106 | manual_review | false | 98s |
| `/Users/jdc/src/autoport` | uv | pypi | 17 | manual_review | false | 75s |
| `/Users/jdc/src/ramp-monorepo/ledger` | uv | pypi | 2 | manual_review | false | 38s |

This pass found scanner integration friction but no fail-open behavior. GuardDog on macOS needs
`--no-sandbox` when run as a host-side advisory scanner, so WhoaThere now adds that argument and
records `guarddog_no_sandbox_for_macos_scanner_compatibility` in the scanner receipt. This does not
grant package execution or copy-back authority. OSV can fail when the environment cannot resolve or
reach `api.osv.dev`; those failures are now recorded as `scanner_network_unavailable` and keep
`scanner_clean=false` instead of being hidden as a generic process error. uv project scanner runs
now map to the PyPI scanner ecosystem, while package-risk assessment still records them as uv.

A follow-up CodexBar-only scanner smoke after the OSV reason-code change produced:

- package-risk verdict: `manual_review`
- scanner receipt: `scanner_clean=false`
- GuardDog: `passed` with the macOS compatibility reason recorded
- OSV: `error` with `scanner_network_unavailable`
- Syft and Grype: `passed`

The scanner-enabled results are intentionally conservative. Scanner outage, scanner timeout, real
Syft/Grype findings, missing baselines, missing publish-age metadata, and missing reputation data
all prevent auto-allow. They do not cause host package execution, and they do not authorize sync-back.

The pass found one useful false-positive class: uv lockfiles include normal registry package
records with `sdist` and `wheels` artifact URLs. Those should not be treated as direct URL
dependencies. The classifier now reads the package source line instead of the entire lockfile block
when deciding whether a package came from a registry, direct URL, VCS, local path, or editable
source. Workspace root editable entries such as `source = { editable = "." }` are ignored because
the root project is assessed separately from its dependencies.

Remaining real-project friction is deliberate for the beta:

- Fresh state without approved package history requires manual review.
- Scanner receipts are useful evidence but are not allowed to authorize sync-back by themselves.
- Packages that create npm command shims or Python console scripts require manual review.
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
- Current live VM validation is blocked until guest reprovision is rerun with sudo after the guest
  agent source digest changed.
