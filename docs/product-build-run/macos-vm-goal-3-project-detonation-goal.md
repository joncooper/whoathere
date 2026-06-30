# WhoaThere macOS Goal 3 Project Detonation Goal

Date: 2026-06-26

## Objective

Build usable local Python project detonation workflows on top of the completed Goal 1 and Goal 2 macOS VM foundation. A developer should be able to run WhoaThere against a supported local Python project or requirements file, have only safe project inputs mirrored into the macOS guest VM, run supported pip behavior inside the guest with fake canaries and bounded execution, and receive an evidence-backed verdict.

This goal keeps sync-back out of scope. The host project must not receive guest outputs.

## Release Claim

WhoaThere can inspect and detonate supported local Python package install, build, and import workflows inside a macOS guest VM using sanitized project inputs, offline guest Python tooling, fake canaries, bounded execution, no host package execution, and no host sync-back.

## Non-Goals

- No AWS Vault, Cloudflare, Linux, Windows, GUI, enterprise proxy, installer, or notarized release work.
- No broad host sync-back of virtualenvs, `site-packages`, lockfiles, or build outputs.
- No arbitrary shell execution exposed through the host protocol.
- No TLS MITM.
- No public malware, destructive payloads, credential theft, persistence, or public exfiltration.
- No claim of universal malware detection or runtime app protection.
- No npm or uv success claim unless the guest toolchains are explicitly provisioned and validated.

## Required Work

### Sanitized Project Mirror

Mirror only allowlisted Python project inputs:

- `pyproject.toml`
- `setup.py`
- `setup.cfg`
- `requirements*.txt`
- explicitly referenced safe constraints/includes inside the workspace
- minimal local package source needed for build/import probes
- small package metadata files needed for local install

Block or exclude:

- `.env`, `.pypirc`, pip credentials, `.npmrc`
- `.ssh`, `.aws`, `.gcp`, `.azure`, `.kube`
- `.git-credentials`, shell history, private keys
- symlink escapes and traversal escapes
- unsafe absolute include paths
- large unrelated files

Record only sanitized counts, byte totals, file classes, excluded secret counts, and blocked reasons. Do not record secret values.

### Guest Project Job

Add a real-project pip detonation path distinct from fixed fixtures. The host must submit a bounded request referencing sanitized project data, not arbitrary host paths.

Supported initial workflows:

- `pip install .`
- `pip install -r requirements.txt` when it can be handled without public registry fetches
- import probe for explicitly selected local module/package names when safely inferable

Public PyPI resolution must fail closed or require manual review unless the artifact is already local in the mirror. Direct URL, VCS, editable, native/binary, and unknown classes remain manual-review or deny by default.

### CLI UX

Support:

```sh
whoathere vm detonate --workspace <path> --execute pip -- install .
whoathere vm detonate --workspace <path> --execute pip -- install -r requirements.txt
```

Dry-run must show what would be mirrored, what would be omitted, and what verdict path applies.

JSON must include command class, mirror summary, job id when executed, verdict, reason codes, canary/network/filesystem signals, `sync_back_enabled=false`, `host_package_execution_enabled=false`, and `raw_canary_values_captured=false`.

Exit codes:

- `0`: observed clean supported project detonation
- `20`: deny, manual review, or fail-closed security outcome
- `64`: misuse
- `70`: internal/helper failure

## Fixtures And Tests

Add non-destructive validation coverage for:

- clean pure Python local package
- `setup.py` canary access
- PEP 517 backend canary access
- import-time canary access
- `.pth` startup hook canary access
- direct URL requirement
- VCS/editable requirement
- unpinned requirement
- requirements include traversal attempt
- symlink escape attempt
- fake secret files that must not be mirrored
- large unrelated file handling

## Validation

Required:

- `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`
- `cargo test --manifest-path whoathere/Cargo.toml`
- `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`
- `swift test` in `whoathere/helpers/macos-vm-helper`
- guest C agent compile
- shell syntax checks for touched scripts
- ASCII scan over docs, scripts, crates, tests, examples, and helper code
- existing live fixture sweep
- existing timeout harness
- new live project-detonation validation script or equivalent focused commands

The new live validation must prove:

- clean local Python project returns `allow_observed_clean`
- malicious Python project fixtures deny or require manual review
- direct/VCS/editable/native/binary/unknown classes do not auto-allow
- secrets are not mirrored
- symlink/traversal escapes are blocked
- no host project files are modified
- VM is stopped afterward and health reports `runtime_process_not_running`

## Sudo Constraint

Avoid repeated sudo during this goal. If guest disk provisioning is unavoidable, batch it into one explicit user-run command and continue with non-privileged work around it. Do not use `chmod +s` on workspace scripts. Do not add passwordless sudoers rules for workspace files.

Future privileged automation should be a root-owned installed helper or LaunchDaemon/SMAppService flow, not a writable repo script.

## Completion Criteria

- Supported local Python project detonation works through the CLI.
- The project mirror is sanitized, bounded, and blocks secrets/path escapes.
- Guest execution uses offline Python/pip tooling inside the VM.
- At least one clean local Python project fixture returns `allow_observed_clean` in the live VM.
- Malicious Python project fixtures deny, fail closed, or require manual review as intended.
- npm and uv behavior remains honest.
- No host package-manager execution occurs.
- No sync-back occurs.
- No host project files are modified.
- No host secrets enter the guest mirror.
- VM is stopped at completion.
- Docs accurately state support and limitations.
- Final validation passes.
- Commit is created and the working tree is clean.
