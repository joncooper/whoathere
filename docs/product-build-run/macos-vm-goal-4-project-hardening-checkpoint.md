# WhoaThere macOS VM Goal 4 Project Hardening Checkpoint

Date: 2026-06-26

## Goal 4 Standard Used

Goal 4 is complete when the existing macOS local Python project detonation path is more automation-ready and compatible with common pure Python projects without weakening the Goal 3 security posture.

The preserved security posture is:

- Apple Silicon macOS guest VM boundary.
- No host package-manager execution.
- No host secrets mirrored into the guest.
- No sync-back to the host project.
- No public PyPI resolver support.
- No native, binary, direct URL, VCS, editable, or unknown auto-allow.
- No runtime application protection claim.

## Implemented Behavior

- `whoathere vm detonate --json` now includes a structured `guest_job` object when the helper returns a valid `whoathere.guest_detonation.v1` response.
- `guest_job` exposes sanitized fields for protocol, schema version, agent version, job id, tool, command class, fixture, status, verdict, reason codes, command exit code, timeout, canary/network/filesystem signals, toolchain availability, stdout/stderr capture flags, raw canary capture flag, sync-back flag, host execution flag, high-risk execution flag, project workflow, project module, project requirements path, VM session id, and exit code.
- The raw helper stdout/stderr fields remain redacted helper diagnostics; package-manager stdout/stderr and raw canaries are not captured or exposed.
- The mirror plan now records `package_data_file_count` and `risky_file_exclusion_count`.
- The project mirror allows narrow safe package data only under inferred Python package directories, currently small `.txt`, `.md`, `.rst`, `.json`, `.toml`, `.yaml`, `.yml`, and `.csv` files.
- Root-level docs and unrelated files remain omitted from the project payload.
- Risky native, binary, archive, compiled object, and source-build marker files are excluded with `detonation_workspace_risky_file_excluded`.
- Any risky-file exclusion makes the project unsafe to execute and adds `project_risky_file_requires_manual_review`, so risky omitted content cannot be silently auto-allowed.
- Hidden/generated directories such as `.cache`, `.tox`, build output, dist output, and egg-info directories are skipped.
- Existing secret handling remains in force, including `.env`, `.pypirc`, `.npmrc`, `.ssh`, `.aws`, `.gcp`, `.kube`, `.git-credentials`, Google ADC files, and related credential material.

## Validation Coverage

Focused tests now cover:

- Structured JSON guest-job evidence and redaction.
- Narrow safe package-data inclusion.
- Risky package/native file exclusion before helper invocation.
- Project payload secret exclusion.
- Direct URL, VCS, editable, public requirement, traversal, symlink, large-file, and native-marker gates.
- Clean project and local requirements cases retaining `allow_observed_clean`.

The live project validation script now exercises:

- Clean local project.
- Local-only requirements.
- Safe package data.
- `setup.py`, PEP 517, import-time, and `.pth` canary cases.
- Public, direct URL, VCS, editable, traversal, native-marker, secret, symlink, and large-file cases.

## Remaining Deferred Work

- No host sync-back yet; this remains detonation and admission evidence, not a complete install replacement.
- No public PyPI resolution.
- No native or binary package approval path.
- No broad package-data policy for arbitrary data files.
- Network evidence remains marker-based for controlled fixtures; robust DNS/HTTPS observation is later work.
- npm and uv project success paths remain unclaimed unless separately provisioned and validated.

## Final Validation Evidence

Passed live against the existing validation VM on 2026-06-26:

```sh
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli --bin whoathere
whoathere/target/debug/whoathere vm start --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
whoathere/target/debug/whoathere vm health --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --json
WHOATHERE_VM_STATE_DIR="$HOME/.whoathere/macos-vm-validation" whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
whoathere/target/debug/whoathere vm suspend --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
```

Live evidence:

- Guest health was proven before validation with `guest_health_proven=true`, Python 3 available, and pip available.
- Clean project, local requirements, and safe package-data project all returned `allow_observed_clean`.
- Safe package-data dry run recorded `mirror_package_data_file_count=1` and `detonation_workspace_safe_package_data_included`.
- Direct URL requirements failed closed before helper invocation.
- Native-marker project recorded `mirror_risky_file_exclusion_count=1`, `detonation_workspace_risky_file_excluded`, and `project_risky_file_requires_manual_review`, then failed closed before helper invocation.
- The validation script exited `0` with `project_detonation_validation=ok`.
- VM suspend reported `runtime_stop_observed=true`.

Final local validation for this checkpoint also includes:

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
rg -n "[^[:ascii:]]" docs/product-build-run/macos-vm-goal-4-project-hardening-checkpoint.md whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh whoathere/crates/whoathere-cli/src/lib.rs
```
