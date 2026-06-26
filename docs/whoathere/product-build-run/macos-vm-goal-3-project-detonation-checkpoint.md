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
- The mirror excludes known secret and credential paths such as `.env`, `.pypirc`, `.npmrc`, `.ssh`, `.aws`, `.kube`, `.git-credentials`, private-key names, and related config directories.
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

Passed locally:

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli --lib vm_detonate -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli --lib project_payload -- --nocapture
swift test
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -fsyntax-only whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-timeout.sh
whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-project-payload.sh
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
```

Current live VM state:

- Validation VM state dir: `/Users/jdc/.whoathere/macos-vm-validation`.
- VM runtime is currently stopped.
- Existing guest provisioning receipt is present and records offline Python/pip tooling.
- Existing provisioned guest-agent digest is `sha256:3230daf4d0ecec6cb7b50af7dfd7c0c3f214b5b2aafe74f7501f58aa1d6c35a1`.
- Current Goal 3 guest-agent build digest is `sha256:3dc223bf4cd5da38f33afa8ced23c9127901abd5196531c1db37f6bcd7a59940`.
- Therefore live Goal 3 project validation requires one guest-agent reprovisioning pass while the VM is stopped.
- `validate-project-detonation.sh` currently exits `64` before live cases with `guest_agent_digest_mismatch=true`, proving it will not accidentally validate Goal 3 against the older guest agent.

Required one-time reprovision command:

```sh
sudo /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh "$HOME/.whoathere/macos-vm-validation"
```

After reprovisioning, run:

```sh
/Users/jdc/src/whoathere/whoathere/target/debug/whoathere vm start --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
WHOATHERE_VM_STATE_DIR="$HOME/.whoathere/macos-vm-validation" /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
/Users/jdc/src/whoathere/whoathere/target/debug/whoathere vm suspend --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
```

## Test Coverage Added

- CLI dry-run proves safe pip project mode, inferred import module, secret exclusion, and no helper invocation.
- CLI execute path proves project payload creation and helper argument forwarding.
- CLI fail-closed path proves public requirements do not invoke the helper.
- Payload test proves excluded secret files and values are not serialized.
- Swift parser test proves project payload flags are accepted.
- Guest agent compile check covers the project payload decoder/materializer.
- Guest-agent project-payload harness proves clean materialization and rejects `../` and metacharacter paths before live VM validation.
- Project validation script covers clean project, local requirements, `setup.py`, PEP 517, import-time, `.pth`, public/direct/VCS/editable/traversal requirements, secret exclusion, symlink escape, large file exclusion, and no host marker/sync-back behavior.

## Known Limitations

- Live Goal 3 project detonation is implemented in code but still needs the validation VM reprovisioned with the new guest agent before it can be proven end to end.
- Requirements support is intentionally narrow: local-only safe inputs are supported; public resolver behavior is deferred.
- The project mirror allowlist is conservative and may exclude legitimate package data until a safe package-data policy is added.
- Native extensions, binary wheels, direct URLs, VCS, editable installs, and unknown classes remain blocked or manual-review by default.
- Network evidence is still marker-based for controlled fixtures; robust DNS/HTTPS observation remains later work.
- There is no sync-back yet, so this is detonation/admission evidence rather than a complete install workflow replacement.
