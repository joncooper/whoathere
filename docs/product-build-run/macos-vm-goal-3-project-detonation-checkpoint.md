# WhoaThere macOS VM Goal 3 Project Detonation Checkpoint

Date: 2026-06-26

## Goal 3 Standard Used

Goal 3 is considered usable when WhoaThere can detonate supported local Python project workflows inside the Apple Silicon macOS guest VM without executing package managers on the host, without mounting host secrets, and without syncing guest outputs back to the host project.

The minimum supported workflows are:

- `whoathere vm detonate --workspace <path> --execute pip -- install .`
- `whoathere vm detonate --workspace <path> --execute pip -- install -r requirements.txt` when the requirements file resolves only to safe local project inputs such as `.`

The host must build a bounded sanitized project mirror, exclude secret-bearing files, block symlink/traversal escapes, deny public/direct/VCS/editable/native/binary dependency forms by default, pass only a bounded payload into the guest, and return structured reason codes. The guest must materialize the payload only under the per-job workspace, run fixed offline pip commands, use fake canaries, probe build/install/import/`.pth` behavior, and produce an evidence-backed allow/deny/fail-closed verdict.

This goal does not claim public PyPI resolution, binary wheel safety, native extension safety, npm/uv project success, runtime application protection, sync-back, or universal malware detection.

## What Is Implemented

- `whoathere vm detonate` now has a project mode for local pip project detonation when no fixture is supplied and `--workspace` points to a supported Python project.
- The CLI mirror planner records allowed files, included relative paths, file classes, byte counts, secret exclusions, symlink escapes, large-file exclusions, and reason codes.
- The mirror allowlist includes Python build config, requirements/constraints files, Python source, package `__init__.py`, and `.pth` startup-hook probes.
- The mirror excludes known secret and credential paths such as `.env`, `.pypirc`, `.npmrc`, `.ssh`, `.aws`, `.gcp`, `.kube`, `.git-credentials`, private-key names, Google ADC files, and related config directories.
- The mirror blocks symlink escapes and unsafe relative paths.
- The CLI enforces payload limits: 128 files, 128 KiB per file, and 512 KiB total mirrored content.
- The CLI serializes a bounded `WTP1` project payload into WhoaThere-managed state under `runs/project-payloads/` and forwards only the payload file path to the helper.
- Unsafe project dependency forms fail before helper invocation, including public requirements, direct URLs, VCS requirements, editable installs, unsafe includes, traversal includes, binary preference flags, and unsupported install targets.
- The Swift helper accepts project payload flags, validates the payload path is absolute and under the configured VM state directory, rejects oversized or non-hex payloads, and includes the payload in the existing guest job protocol.
- The guest agent decodes the `WTP1` payload, validates every relative path, materializes files under the per-job workspace only, and runs fixed offline pip commands for `pip_project_install` and `pip_requirements_install`.
- The guest project workflow probes build/install behavior, import-time behavior when a safe module can be inferred, and `.pth` startup-hook behavior.
- Host package execution remains disabled. Host sync-back remains disabled.
- The CLI detonation helper supervision timeout now allows long enough for bounded project pip execution while the guest still enforces per-job timeouts.
- New validation script: `whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh`.
- The project validation script preflights the provisioned guest-agent SHA-256 and fails fast with the exact reprovisioning command when the VM disk still contains an older guest agent.
- New guest-agent harness: `whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-project-payload.sh` proves `WTP1` payload materialization and path rejection without needing a live VM.

## Supported Verdict Posture

| Input class | Goal 3 behavior |
| --- | --- |
| Clean local pure Python project with `setup.py`/`pyproject.toml` | Detonate in VM; allow only if clean |
| Local `requirements.txt` containing `.` | Detonate in VM; allow only if clean |
| `setup.py` canary access | Deny on guest canary marker |
| PEP 517 backend canary access | Deny on guest canary marker |
| Import-time canary access | Deny on guest canary marker |
| `.pth` startup hook canary access | Deny on guest canary marker |
| Public or unpinned requirements | Fail closed before helper invocation |
| Direct URL, VCS, editable requirements | Fail closed before helper invocation |
| Traversal or symlink escape | Block/fail closed before guest execution |
| Secret files | Excluded from mirror; values are not recorded |
| Large allowlisted files | Excluded and recorded by count/reason |
| npm/uv project workflows | Not claimed; remain fail closed unless separately validated |

## Validation State

Passed locally on 2026-06-26:

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
swift test
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -fsyntax-only whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-project-payload.sh
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-detonation-fixtures.sh
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-timeout.sh
whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-timeout.sh
whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-project-payload.sh
```

The ASCII scan returned no matches across README, product-build docs, scripts, Rust workspace files, examples, tests, probe images, and the macOS VM helper tree.

Passed live against the validation VM on 2026-06-26:

```sh
whoathere/target/debug/whoathere vm start --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
WHOATHERE_VM_STATE_DIR="$HOME/.whoathere/macos-vm-validation" whoathere/helpers/macos-vm-helper/scripts/validate-detonation-fixtures.sh
WHOATHERE_VM_STATE_DIR="$HOME/.whoathere/macos-vm-validation" whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
whoathere/target/debug/whoathere vm suspend --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
whoathere/target/debug/whoathere vm status --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --json
```

Live evidence summary:

- Validation VM state dir: `/Users/jdc/.whoathere/macos-vm-validation`.
- Provisioned signed guest-agent digest: `sha256:550b952aabd9366ab294f2ddc0df8d2a02dbff8d6b0ec3f8b816efd0e63b41df`.
- The validation script now computes the same ad-hoc-signed guest-agent digest before comparing against the provisioning receipt, so it does not falsely reject a correctly provisioned guest.
- Guest health proof was present and verified: `guest_health_proven=true`, `host_runtime_health_proven=true`, `runtime_pid_alive=true`, `vm_session_id=46b1f1981aafa1b838459f86595bc74e`.
- Guest toolchain proof matched the scoped release target: `python3=true`, `pip=true`, `npm=false`, `uv=false`.
- `validate-detonation-fixtures.sh` exited `0` with `detonation_fixture_validation=ok`.
- Fixture sweep proved pip clean allow, pip setup/PEP 517/import/`.pth` canary deny, risky native/direct classes manual review, npm/uv fail-closed where guest tooling is absent, `sync_back_enabled=false`, `host_package_execution_enabled=false`, and `raw_canary_values_captured=false`.
- `validate-project-detonation.sh` exited `0` with `project_detonation_validation=ok`.
- Project validation proved clean local project and local `requirements.txt` install return `allow_observed_clean`; setup, PEP 517, import-time, and `.pth` canary cases return deny/fail-closed; public, direct URL, VCS, editable, and traversal requirements fail before helper invocation; secret files are excluded from the mirror; symlink escapes and large files are recorded without host sync-back.
- VM cleanup succeeded with `runtime_stop_observed=true`.
- Final status confirmed `runtime_pid_alive=false`, `runtime_pid_present=false`, and readiness is fail-closed while stopped.

## Test Coverage Added

- CLI dry-run proves safe pip project mode, inferred import module, secret exclusion, and no helper invocation.
- CLI execute path proves project payload creation and helper argument forwarding.
- CLI fail-closed path proves public requirements do not invoke the helper.
- Payload test proves excluded secret files and values are not serialized.
- Swift parser test proves project payload flags are accepted.
- Guest agent compile check covers the project payload decoder/materializer.
- Guest-agent project-payload harness proves clean materialization and rejects `../` and metacharacter paths before live VM validation.
- Project validation script covers clean project with explicit `allow_observed_clean` verdict assertions, local requirements, `setup.py`, PEP 517, import-time, `.pth`, public/direct URL/VCS/editable/traversal requirements, secret exclusion, symlink escape, large file exclusion, and no host marker/sync-back behavior.

## Known Limitations

- Requirements support is intentionally narrow: local-only safe inputs are supported; public resolver behavior is deferred.
- The project mirror allowlist is conservative and may exclude legitimate package data until a safe package-data policy is added.
- Native extensions, binary wheels, direct URLs, VCS, editable installs, and unknown classes remain blocked or manual-review by default.
- Network evidence is still marker-based for controlled fixtures; robust DNS/HTTPS observation remains later work.
- There is no sync-back yet, so this is detonation/admission evidence rather than a complete install workflow replacement.
