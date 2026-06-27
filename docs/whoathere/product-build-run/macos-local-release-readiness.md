# WhoaThere macOS Local Release Readiness

Date: 2026-06-27

## Release Target

The target release is an Apple Silicon macOS-only, local-first, CLI-only WhoaThere build that a developer can realistically use to detonate and admit supported npm and Python package workflows inside a macOS guest VM.

The release must preserve these invariants:

- No host package-manager execution for high-risk workflows.
- No host secrets mirrored into the VM.
- No public resolver fallback unless explicitly designed, gated, and tested.
- No native, binary, direct URL, VCS, editable, or unknown artifact auto-allow.
- No sync-back unless separately implemented with a deny-by-default whitelist and live validation.
- No raw canaries, secrets, or package-manager stdout/stderr in structured evidence.
- No claim of universal malware detection, runtime application protection, or safe arbitrary native execution.

## Release Criteria

The macOS local release is ready only when all of the following are true:

1. VM lifecycle UX is usable: `doctor`, `vm status`, `vm init`, `vm start`, `vm health`, `vm suspend`, `vm reset`, and `vm prune` have clear diagnostics, no hidden privilege requirements, and fail closed.
2. A signed or otherwise explicitly verified VM image/helper path is documented and enforced honestly.
3. Supported workflow UX is clear for pip local projects, local-only requirements, npm workflows if claimed, and uv workflows if claimed.
4. Supported workflows execute package-manager behavior only inside the guest VM.
5. The host mirror excludes secrets, symlink/traversal escapes, unsafe dependency forms, and unsupported native/binary artifacts before guest execution.
6. Guest execution returns structured evidence for install/build/import or CLI probes, canary access, filesystem signals, network or egress signals, verdict, and reason codes.
7. Sync-back is either explicitly out of scope for the release or implemented with a narrow tested whitelist.
8. External scanner/comparator adapters are integrated as evidence sources where practical, while WhoaThere remains authoritative for verdicts.
9. Non-destructive red-team fixtures prove that known malicious npm/PyPI patterns are detected or blocked before unsafe host impact.
10. Packaging, onboarding, troubleshooting, limitations, and uninstall docs are sufficient for a developer preview release.

## Current Audit

| Area | Status | Evidence |
| --- | --- | --- |
| Apple Silicon macOS VM boundary | Partial | VM lifecycle, helper, provisioning, guest-health, and detonation commands exist, but release packaging and signature/notarization gates remain incomplete. |
| VM start/health/suspend lifecycle | Improved in this checkpoint | Live validation starts the signed helper VM, proves guest health over vsock, reports Python/pip available and npm/uv unavailable, suspends with observed runtime stop, and confirms final stopped state. |
| Host package-manager isolation | Strong for claimed pip paths | Goals 3 and 4 validate local pip project and local-only requirements detonation inside the guest without host package-manager execution. |
| Secret exclusion | Strong for claimed pip paths | Sanitized mirror excludes known secret paths, credential files, symlink escapes, traversal, and large unsafe payloads. |
| Python local project detonation | Implemented | Live validation covers clean project, local requirements, safe package data, setup.py canary, PEP 517 canary, import-time canary, and `.pth` canary cases. |
| npm detonation | Not release-ready | Offline Node/npm provisioning support has been added, but successful npm detonation is not claimed until the validation VM is reprovisioned and live npm fixture/project workflows pass. |
| uv detonation | Not release-ready | Offline uv provisioning support has been added, but uv execution remains unclaimed until the validation VM is reprovisioned and live uv fixture/project workflows pass. |
| Public package acquisition | Not implemented | Public PyPI/npm resolver behavior remains blocked or deferred; there is no public fallback claim. |
| Native and binary artifacts | Fail closed/manual review | Native markers, binary wheels, direct URLs, VCS, editable, and unknown classes are not auto-allowed. |
| Network evidence | Partial | Controlled fixtures and reason codes exist, but robust DNS/HTTPS observation is still marker-based rather than a full network monitor. |
| Sync-back | Explicitly out of scope for preview | Current posture is detonation/admission evidence only. Host sync-back remains disabled and is not required for the preview release gate. Future sync-back still requires a deny-by-default whitelist and live validation before any claim changes. |
| Doctor/readiness UX | Improved in this checkpoint | `whoathere doctor --json --state-dir <dir> --helper <path>` now reports release readiness, the inspected VM state directory, guest provisioning receipt/toolchain status, implemented workflows, fail-closed workflows, manual-review classes, blocking reason codes, and next actions. |
| Default VM manifest loading | Implemented for CLI status/readiness | `vm status` and `doctor` now load `<state-dir>/bundle/image.manifest` by default, tolerate the helper restore-image manifest shape, and report signature verification as the real blocker instead of falsely reporting a missing manifest. |
| Packaging/onboarding | Partial | [macOS local-first preview runbook](macos-local-first-preview-runbook.md) now documents first-run build, signing, VM init, provisioning, health, detonation validation, limitations, and cleanup. Installer, signed artifacts, codesign/notarization verification, and release packaging still need a release pass. |
| Comparator/red-team gate | Not complete | Existing fixtures are useful, but the release still needs a deliberate comparator pass against GuardDog, OSV/pip-audit class tools, and recent npm/PyPI attack patterns. |

## Current Verdict

WhoaThere is not yet ready for the macOS-only local-first release target.

The current tree is a credible VM-backed Python local project detonation prototype with strong fail-closed behavior for the workflows it claims. It is not yet a ready-to-use developer release because npm, uv, public package acquisition, release packaging, and comparator/red-team validation are still incomplete. Sync-back is deliberately disabled for this preview rather than an unresolved release requirement.

## Machine-Readable Gate

`whoathere doctor --json` now includes:

- `guest_provisioning`
- `release_readiness_schema`
- `release_stage`
- `release_ready`
- `release_blocking_reason_codes`
- `implemented_workflows`
- `fail_closed_workflows`
- `manual_review_classes`
- `next_actions`

For this checkpoint, `release_ready` must remain `false`. A future loop may flip it only after the release criteria above are implemented, validated, and documented.

## Validation Evidence For This Checkpoint

Passed for this release-readiness slice on 2026-06-27:

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
rg -n "[^[:ascii:]]" docs/whoathere/product-build-run/macos-local-release-readiness.md whoathere/crates/whoathere-cli/src/lib.rs whoathere/crates/whoathere-macos-vm/src/lib.rs
cargo run --quiet --manifest-path whoathere/Cargo.toml --bin whoathere -- doctor --json
cargo run --quiet --manifest-path whoathere/Cargo.toml --bin whoathere -- doctor --json --state-dir /private/tmp/whoathere-doctor-state
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli --bin whoathere
whoathere/target/debug/whoathere vm status --json --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
whoathere/target/debug/whoathere doctor --json --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
swift test
swift build
./scripts/sign-local-helper.sh
whoathere/target/debug/whoathere vm start --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
whoathere/target/debug/whoathere vm health --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
whoathere/target/debug/whoathere vm suspend --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
whoathere/target/debug/whoathere vm health --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
sh -n whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -fsyntax-only whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
```

The `doctor --json` smokes reported `release_ready=false`, `high_risk_allowed=false`, `vm_ready=false`, the inspected VM state directory, implemented pip/local detonation workflows, fail-closed npm/uv/public-resolution/sync-back workflows, and release blockers for npm, uv, public package resolution, packaging, comparator/red-team validation, scanner availability, VM runtime readiness, and signature/notarization. Sync-back is reported as disabled for the preview rather than as a readiness blocker.

The live validation VM smoke now reports `manifest_present=true`, `manifest_path=/Users/jdc/.whoathere/macos-vm-validation/bundle/image.manifest`, and `macos_vm_manifest_signature_not_verified`; it no longer reports `macos_vm_image_manifest_missing` for the prepared validation state directory.

This checkpoint adds a structured guest provisioning summary to `vm status --json` and `doctor --json`. On the current validation VM, the summary proves the receipt is present and Python tooling is installed, but Node/npm and uv are not recorded in the stale receipt:

```text
guest_provisioning.reason_codes=["macos_vm_guest_node_runtime_not_provisioned", "macos_vm_guest_uv_binary_not_provisioned"]
guest_provisioning.python_runtime_status=installed
guest_provisioning.python_wheels_status=installed
guest_provisioning.wheel_package_status=installed
guest_provisioning.node_runtime_status=null
guest_provisioning.uv_binary_status=null
```

Those reason codes now appear in `release_blocking_reason_codes`, so stale or incomplete provisioning cannot be mistaken for npm/uv release readiness.

The helper lifecycle smoke showed that `swift build` replaces the signed helper binary, so the helper must be re-signed before VM start. After re-signing, start returned `exit_code=0`, health returned `guest_health_proven=true`, `guest_toolchain_python3_available=true`, `guest_toolchain_pip_available=true`, `guest_toolchain_npm_available=false`, and `guest_toolchain_uv_available=false`. Updated suspend behavior returned `exit_code=0`, `runtime_stop_observed=true`, and `suspend_semantics=force_stop`. Final health returned fail-closed with `runtime_process_not_running`, confirming the VM was stopped.

Offline provisioning now supports copying host or repo-provided Node/npm and uv tooling into the guest under `/usr/local/whoathere`. The guest agent uses a fixed WhoaThere-owned PATH for tool discovery and detonation. Static validation passed, but live npm/uv proof is still pending because `sudo ./scripts/provision-guest-readiness.sh /Users/jdc/.whoathere/macos-vm-validation` requires an interactive sudo password in this environment.

Live VM validation is not required for this checkpoint because the implementation slice changes only readiness reporting and documentation. The next implementation slices that change VM behavior must include live VM checks for every claimed workflow.

## Next Recommended Slice

Focus on VM lifecycle and onboarding UX before expanding package-manager coverage:

1. Run `doctor`, `vm status`, `vm init`, `vm start`, `vm health`, `vm suspend`, `vm reset`, and `vm prune` against the validation VM from a clean user perspective.
2. Reprovision the stopped validation VM with `sudo WHOATHERE_NODE_RUNTIME_DIR=/Users/jdc/.nvm/versions/node/v22.22.3 WHOATHERE_UV_BINARY=/Users/jdc/.local/bin/uv /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh /Users/jdc/.whoathere/macos-vm-validation`, then rerun status and health to prove the receipt and live guest report `guest_toolchain_npm_available=true` and `guest_toolchain_uv_available=true`.
3. Run the npm and uv fixture suites. Keep npm/uv release claims fail-closed until those live checks pass.
4. Turn the helper signing requirement into first-run onboarding so users do not run an unsigned helper after `swift build`.
5. Keep sync-back disabled for the preview unless a separately tested deny-by-default whitelist is implemented.
6. Decide whether force-stop is acceptable release behavior for `vm suspend`, or whether guest-requested stop must be made reliable before release.
7. Make remaining failure messages actionable without exposing secrets or raw guest output.
8. Use the macOS local-first preview runbook as the onboarding baseline and keep it updated as npm/uv, sync-back, scanner, and packaging claims change.

After that, move to npm VM detonation. If npm cannot be made reliable without extra guest provisioning, keep npm explicitly fail-closed and document the blocker instead of expanding the release claim.
