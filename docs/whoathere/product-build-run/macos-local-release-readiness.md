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
| Apple Silicon macOS VM boundary | Partial | VM lifecycle, helper, provisioning, guest-health, detonation commands, local-only package policy, and preview packaging exist, but live npm/uv proof and release signing/notarization gates remain incomplete. |
| VM start/health/suspend lifecycle | Strong for current preview VM | Live validation starts the entitlement-signed helper VM, proves guest health over vsock, reports Python/pip available and npm/uv unavailable, reports `vm_ready=true` while host and guest health proofs are present, suspends with observed runtime stop, and confirms final stopped state. |
| Host package-manager isolation | Strong for claimed pip paths | Goals 3 and 4 validate local pip project and local-only requirements detonation inside the guest without host package-manager execution. |
| Secret exclusion | Strong for claimed pip paths | Sanitized mirror excludes known secret paths, credential files, symlink escapes, traversal, and large unsafe payloads. |
| Python local project detonation | Implemented | Live validation covers clean project, local requirements, safe package data, setup.py canary, PEP 517 canary, import-time canary, and `.pth` canary cases. |
| npm detonation | Host planner improved, not release-ready | The CLI now supports a narrow local npm project mirror plan for `npm install` and `npm ci` when `package.json` has no external dependency resolution and the workspace contains no native/risky artifacts. The Swift helper and guest agent accept that project payload path, but successful npm detonation is not claimed until the validation VM is reprovisioned with Node/npm and live npm fixture/project workflows pass. Public npm dependencies remain fail-closed. |
| uv detonation | Host planner improved, not release-ready | The CLI now supports a narrow local `uv pip install` project mirror plan by reusing the pip local-project safety rules, and the Swift helper/guest agent accept `uv_pip_project_install` and `uv_pip_requirements_install` payloads. `uv sync` remains deferred until lock/source policy is explicit. Live uv execution remains unclaimed until the validation VM is reprovisioned with uv and live fixture/project workflows pass. |
| Package acquisition policy | Implemented local-only preview policy | Public PyPI/npm resolver behavior remains blocked and there is no public fallback claim. The preview policy is `local_only_no_public_resolver`: supported workflows use local projects, local requirements, and no-external-dependency npm project plans only. |
| Native and binary artifacts | Fail closed/manual review | Native markers, binary wheels, direct URLs, VCS, editable, and unknown classes are not auto-allowed. |
| Network evidence | Partial | Controlled fixtures and reason codes exist, but robust DNS/HTTPS observation is still marker-based rather than a full network monitor. |
| Sync-back | Explicitly out of scope for preview | Current posture is detonation/admission evidence only. Host sync-back remains disabled and is not required for the preview release gate. Future sync-back still requires a deny-by-default whitelist and live validation before any claim changes. |
| Doctor/readiness UX | Improved in this checkpoint | `whoathere doctor --json --state-dir <dir> --helper <path>` now reports release readiness, the inspected VM state directory, guest provisioning receipt/toolchain status, package acquisition policy, implemented workflows, fail-closed workflows, manual-review classes, blocking reason codes, next actions, separate VM lifecycle/runtime readiness, and a derived `guest_reprovision_command` when guest provisioning is missing or stale and the helper script path can be resolved. A stopped VM is visible as `vm_runtime_ready=false` but is not a release blocker when lifecycle readiness is otherwise proven. |
| Default VM manifest loading | Implemented for CLI status/readiness | `vm status` and `doctor` now load `<state-dir>/bundle/image.manifest` by default, tolerate the helper restore-image manifest shape, accept helper-created `local_developer_verified` preview manifests for lifecycle gating, and still reject stale or unverified manifests. `vm upgrade-local-manifest --execute` explicitly upgrades only legacy helper-created local preview manifests after bundle validation. Production release signing/notarization remains a separate blocker. |
| Scanner adapters | Advisory for no-sync preview | External scanner binaries are still reported and remain required before any future auto-sync/auto-allow release. They are no longer a hard blocker for the current detonation/admission-only preview because sync-back is disabled and `whoathere vm red-team-gate` provides local fixture-safe comparator coverage. |
| Packaging/onboarding | Preview implemented | [macOS local-first preview runbook](macos-local-first-preview-runbook.md) now documents first-run build, signing, VM init, provisioning, health, detonation validation, limitations, cleanup, and the repeatable preview tarball script. The package script builds the release CLI/helper, signs them locally, runs local gates, writes a checksum, and was validated from an extracted archive. Developer ID signing, notarization, and installer UX remain outside the preview package claim. |
| Comparator/red-team gate | Implemented for fixture-safe local gate | `whoathere vm red-team-gate` now runs 18 deterministic local cases covering static lifecycle/PEP 517 signals, dynamic npm/PyPI exfiltration shapes, DNS/HTTPS exfiltration, delayed CI activation, native/platform/direct-source risk, stale/wrong-context evidence, and raw-material rejection. It uses comparator labels for GuardDog/OpenSSF Package Analysis-style coverage without requiring public network or external scanner binaries. |

## Current Verdict

WhoaThere is not yet ready for the macOS-only local-first release target.

The current tree is a credible VM-backed Python local project detonation prototype with strong fail-closed behavior for the workflows it claims, plus host-side local npm and uv project planners for no-external-dependency workspaces, a local-only package acquisition policy, a repeatable preview package path, and a validation VM whose manifest, lifecycle, and guest health can be proven. It is not yet a ready-to-use developer release because live npm/uv guest tooling/proof and signature/notarization are still incomplete. Sync-back is deliberately disabled for this preview rather than an unresolved release requirement, so missing external scanner binaries are advisory until an auto-sync claim exists.

## Machine-Readable Gate

`whoathere doctor --json` now includes:

- `guest_provisioning`
- `guest_reprovision_command`
- `release_readiness_schema`
- `release_stage`
- `release_ready`
- `release_blocking_reason_codes`
- `package_acquisition_policy`
- `implemented_workflows`
- `fail_closed_workflows`
- `manual_review_classes`
- `next_actions`
- `vm_lifecycle_ready`
- `vm_lifecycle_reason_codes`
- `vm_runtime_ready`
- `guest_reprovision_required`
- `guest_reprovision_admin_required`
- `guest_reprovision_operator_action`
- `guest_reprovision_command`

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
cargo run --quiet --manifest-path whoathere/Cargo.toml --bin whoathere -- vm red-team-gate --json
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli vm_detonate_npm_project
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli vm_detonate_uv
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm local_developer_verified
swift test
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -fsyntax-only whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli --bin whoathere
whoathere/target/debug/whoathere vm status --json --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
whoathere/target/debug/whoathere doctor --json --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
swift test
swift build
./scripts/sign-local-helper.sh .build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
whoathere/target/debug/whoathere vm upgrade-local-manifest --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
whoathere/target/debug/whoathere vm start --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
whoathere/target/debug/whoathere vm health --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
whoathere/target/debug/whoathere doctor --json --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
whoathere/target/debug/whoathere vm suspend --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
whoathere/target/debug/whoathere vm health --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
sh -n whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh
sh -n whoathere/helpers/macos-vm-helper/scripts/provision-command-lib.sh
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-local-vm.sh
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
sh -n scripts/whoathere-package-macos-preview.sh
scripts/whoathere-package-macos-preview.sh
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -fsyntax-only whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
```

The `doctor --json` smokes reported `release_ready=false`, `high_risk_allowed=false`, the inspected VM state directory, `package_acquisition_policy=local_only_no_public_resolver`, implemented pip/local detonation workflows, fail-closed npm/uv/public-resolution/sync-back workflows, and release blockers for npm guest tooling/proof, uv guest tooling/proof, and signature/notarization. While the VM was running with host and guest health proofs, doctor reported `vm_lifecycle_ready=true`, `vm_runtime_ready=true`, and `vm_reason_codes=[]`; after suspend, doctor reported `vm_lifecycle_ready=true`, `vm_runtime_ready=false`, and `vm_reason_codes=["macos_vm_runtime_not_verified"]`, while `release_blocking_reason_codes` no longer included `macos_vm_runtime_not_verified`. Sync-back is reported as disabled for the preview rather than as a readiness blocker. Scanner availability is reported with `scanner_release_blocking=false` and `scanner_release_scope=required_before_auto_sync_not_no_sync_preview`. Focused unit tests verify `guest_reprovision_command` is emitted from a package-shaped helper layout when the guest provisioning receipt is missing, that helper-derived lifecycle/runtime health removes stale marker-based VM blockers, and that stopped runtime state stays visible without blocking release readiness.

The red-team fixture gate passed with `passed=true`, `case_count=18`, `public_network_used=false`, and `external_scanners_required=false`. The gate does not execute arbitrary packages and does not replace scanner adapters; it proves the local fixture-safe static/dynamic evidence paths and binding checks catch or reject representative attack shapes without leaking canaries or local paths.

The npm local project planner tests passed for a no-dependency local package, helper payload forwarding, and public dependency fail-closed behavior. The uv local project planner tests passed for `uv pip install .`, helper payload forwarding, and `uv sync` fail-closed behavior. The helper build/tests and guest C syntax check passed after enabling npm and uv project payload handling. This proves host-side npm/uv project preparation and guest request plumbing, not live npm/uv execution; live npm/uv remains blocked until Node/npm and uv are provisioned and the validation VM returns clean guest evidence.

The live validation VM smoke now reports `manifest_present=true`, `manifest_valid=true`, and `manifest_path=/Users/jdc/.whoathere/macos-vm-validation/bundle/image.manifest`; it no longer reports `macos_vm_image_manifest_missing` or `macos_vm_manifest_signature_not_verified` for the prepared validation state directory. The existing validation bundle was explicitly upgraded with `whoathere vm upgrade-local-manifest --execute`, which rewrote only the legacy helper-created `signature_status=signature_verification_not_implemented` marker to `local_developer_verified` after bundle validation. Newly helper-created preview manifests use `signature_status=local_developer_verified` for local lifecycle gating. This does not satisfy the final `release_signature_notarization_not_complete` release blocker.

A focused helper smoke with a temporary manifest using `signature_status=local_developer_verified`
returned no manifest signature or schema validation reasons. It still returned fail-closed lifecycle
reasons for missing disk, config, auxiliary storage, hardware model, machine identifier, and guest
readiness materials, which is the expected behavior for an incomplete temporary bundle.

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

Offline provisioning now supports copying host or repo-provided Node/npm and uv tooling into the guest under `/usr/local/whoathere`. The guest agent uses a fixed WhoaThere-owned PATH for tool discovery and detonation. Static validation passed, but live npm/uv proof is still pending because the emitted `sudo ... provision-guest-readiness.sh /Users/jdc/.whoathere/macos-vm-validation` command requires an interactive sudo password in this environment.

The provisioning and project validation scripts now emit a concrete machine-specific reprovision
command when root-owned guest tooling is missing or stale. `vm status` and `doctor` also report
`guest_reprovision_required`, `guest_reprovision_admin_required`, and
`guest_reprovision_operator_action`, so the admin boundary is explicit rather than hidden in a
failing install path. On this workstation the non-root smoke printed
`WHOATHERE_NODE_RUNTIME_DIR=/Users/jdc/.nvm/versions/node/v22.22.3` and
`WHOATHERE_UV_BINARY=/Users/jdc/.local/bin/uv` in the suggested `sudo` command. A non-interactive
attempt to run that command failed before mutation because sudo required a terminal/password:
`sudo: a terminal is required to read the password`.

The preview packaging path now has `scripts/whoathere-package-macos-preview.sh`. It validates the
Rust workspace, builds the release CLI, locally signs the CLI, runs Swift helper tests, builds and
signs the release helper, runs the local red-team fixture gate, stages helper scripts and docs, and
writes a tarball plus SHA-256 checksum under ignored `dist/`. It deliberately reports
`notarization_status=not_performed`; final Developer ID/notarization work remains open.

The packaging script was run end to end on this host and produced a preview tarball plus checksum.
After extracting the archive to `/private/tmp`, the packaged `bin/whoathere --help` worked and the
packaged `validate-project-detonation.sh` resolved the package-local release helper and failed
closed at the missing guest provisioning receipt with a package-local reprovision command.

The latest npm/uv planner slices changed host planner, Swift helper, and guest-agent behavior. They were validated with unit tests, helper build/tests, guest C syntax checks, and live `doctor` fail-closed readiness output. Live npm/uv detonation is still not claimed because the stopped validation VM must first be reprovisioned with Node/npm and uv tooling through the interactive sudo step above.

## Next Recommended Slice

Focus on live VM validation and packaging UX before expanding package-manager coverage:

1. Reprovision the stopped validation VM with the exact `sudo ... provision-guest-readiness.sh ...` command emitted by `doctor`, `provision-guest-readiness.sh`, or `validate-project-detonation.sh`, then rerun status and health to prove the receipt and live guest report `guest_toolchain_npm_available=true` and `guest_toolchain_uv_available=true`.
2. Run the npm and uv fixture suites. Keep npm/uv release claims fail-closed until those live checks pass.
3. Exercise `scripts/whoathere-package-macos-preview.sh` as the release candidate build path, then add Developer ID signing/notarization or keep the artifact clearly labeled as a local preview.
4. Keep sync-back disabled for the preview unless a separately tested deny-by-default whitelist is implemented.
5. Decide whether force-stop is acceptable release behavior for `vm suspend`, or whether guest-requested stop must be made reliable before release.
6. Make remaining failure messages actionable without exposing secrets or raw guest output.
7. Run `whoathere vm red-team-gate --json` on every release candidate and keep the macOS local-first preview runbook updated as npm/uv, sync-back, scanner, and packaging claims change.

After that, run live npm and uv VM detonation for no-external-dependency local projects. If either cannot be made reliable without extra guest provisioning, keep that workflow explicitly fail-closed and document the blocker instead of expanding the release claim.
