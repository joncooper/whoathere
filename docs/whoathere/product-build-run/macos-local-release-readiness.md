# WhoaThere macOS Local Release Readiness

Date: 2026-06-27

## Release Target

The target release is an Apple Silicon macOS-only, local-first, CLI-only WhoaThere build that a developer can realistically use to detonate and admit supported npm and Python package workflows inside a macOS guest VM.

The release must preserve these invariants:

- No host package-manager execution for high-risk workflows.
- No host secrets mirrored into the VM.
- No public resolver fallback unless explicitly designed, gated, and tested.
- No native, binary, direct URL, VCS, editable, or unknown artifact auto-allow.
- No sync-back outside the explicit beta path with a deny-by-default whitelist and live validation.
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
7. Sync-back is implemented only with a narrow tested whitelist, clean VM evidence, and a current authenticated sync-validation receipt.
8. External scanner/comparator adapters are integrated as evidence sources where practical, while WhoaThere remains authoritative for verdicts.
9. Non-destructive red-team fixtures prove that known malicious npm/PyPI patterns are detected or blocked before unsafe host impact.
10. Local package memory, last-known-good selection, fresh-release cooldowns, and suspicious-diff checks are implemented as pre-beta risk gates.
11. Packaging, onboarding, troubleshooting, limitations, and uninstall docs are sufficient for a developer preview release.

## Current Audit

| Area | Status | Evidence |
| --- | --- | --- |
| Apple Silicon macOS VM boundary | Release-candidate gate implemented | VM lifecycle, helper, provisioning, guest-health, detonation commands, local-only package policy, preview packaging, authenticated live npm/uv validation receipts, and authenticated Developer ID notarization receipts are now part of the machine-readable release gate. |
| VM start/health/suspend lifecycle | Strong for current preview VM | Live validation starts the entitlement-signed helper VM, proves guest health over vsock, reports offline Python/pip, Node/npm, and uv toolchains available in the current provisioning receipt, reports `vm_ready=true` while host and guest health proofs are present, suspends with observed runtime stop, and confirms final stopped state. `vm status` and `doctor` now summarize the last shutdown proof from `bundle/shutdown.json`, including `stop_method`, reason codes, and whether that stop is acceptable for the no-sync preview. |
| Host package-manager isolation | Strong for claimed pip paths | Goals 3 and 4 validate local pip project and local-only requirements detonation inside the guest without host package-manager execution. |
| Secret exclusion | Strong for claimed pip paths | Sanitized mirror excludes known secret paths, credential files, symlink escapes, traversal, and large unsafe payloads. |
| Python local project detonation | Implemented | Live validation covers clean project, local requirements, safe package data, setup.py canary, PEP 517 canary, import-time canary, and `.pth` canary cases. |
| npm detonation | Implemented for local no-external-dependency projects | The CLI supports a narrow local npm project mirror plan for `npm install` and `npm ci` when `package.json` has no external dependency resolution and the workspace contains no native/risky artifacts. `--execute` checks the root-owned guest provisioning receipt before preparing a project payload or invoking the helper, so npm fails closed unless Node/npm, disabled host secret/home/high-risk states, and current guest-agent provisioning are proven. The live release gate now verifies clean npm install/ci cases in the VM and keeps public npm dependencies fail-closed. |
| uv detonation | Implemented for local `uv pip install .` projects | The CLI supports a narrow local `uv pip install` project mirror plan by reusing the pip local-project safety rules, and the Swift helper/guest agent accept `uv_pip_project_install` and `uv_pip_requirements_install` payloads. The guest-agent uv path uses the provisioned Python plus offline pip/setuptools/wheel inputs with `--no-build-isolation`, avoiding public-index build isolation for clean local project installs. The live release gate now verifies clean uv project installs and canary import-time denial in the VM. `uv sync` remains deferred until lock/source policy is explicit. |
| Package acquisition policy | Implemented local-only preview policy | Public PyPI/npm resolver behavior remains blocked and there is no public fallback claim. The preview policy is `local_only_no_public_resolver`: supported workflows use local projects, local requirements, and no-external-dependency npm project plans only. |
| Native and binary artifacts | Fail closed/manual review | Native markers, binary wheels, direct URLs, VCS, editable, and unknown classes are not auto-allowed. |
| Network evidence | Partial | Controlled fixtures and reason codes exist, but robust DNS/HTTPS observation is still marker-based rather than a full network monitor. |
| Sync-back | Beta allowlist implemented | Host sync-back is available only through `whoathere vm detonate --sync-back --package-risk-receipt <path>` after clean VM evidence and clean authenticated package-risk evidence from the same state directory, bound to the same workspace digest. The host validates a bounded guest archive, rejects traversal, symlink escapes, native/binary outputs, canary/secret material, wrong context, stale evidence, and unsupported paths, stages approved files, rolls back failed applies, and writes a state-authenticated `bundle/sync-validation.json` only after successful sync. |
| Doctor/readiness UX | Improved in this checkpoint | `whoathere doctor --json --state-dir <dir> --helper <path>` now reports release readiness, the inspected VM state directory, guest provisioning receipt/toolchain status, release-validation receipt status, package acquisition policy, implemented workflows, fail-closed workflows, manual-review classes, blocking reason codes, next actions, separate VM lifecycle/runtime readiness, and a derived `guest_reprovision_command` when guest provisioning is missing or stale and the helper script path can be resolved. Release-validation, sync-validation, and notarization receipts must include state-local `receipt_auth` before they can clear release blockers; present but unsigned JSON is reported as untrusted. Text-mode `doctor` and `vm status` keep large helper payloads summarized with byte counts instead of dumping nested JSON. A stopped VM is visible as `vm_runtime_ready=false` but is not a release blocker when lifecycle readiness is otherwise proven. |
| Default VM manifest loading | Implemented for CLI status/readiness | `vm status` and `doctor` now load `<state-dir>/bundle/image.manifest` by default, tolerate the helper restore-image manifest shape, accept helper-created `local_developer_verified` preview manifests for lifecycle gating, and still reject stale or unverified manifests. `vm upgrade-local-manifest --execute` explicitly upgrades only legacy helper-created local preview manifests after bundle validation. Production release signing/notarization remains a separate blocker. |
| Scanner adapters | Functional advisory evidence layer | `whoathere scanners list`, `scanners bootstrap-plan`, and `scanners run` now provide scanner availability, bootstrap, dry-run, and normalized execution evidence for GuardDog, OSV-Scanner, pip-audit, Syft, and Grype, with Trivy and Scorecard report-only. Executed scanner receipts can be state-authenticated with `--state-dir`; clean scanner evidence without state-local auth is report-only for package-risk decisions. Scanner availability is still not a hard blocker for the current local-only sync beta because public package acquisition remains blocked. Missing or dirty scanner evidence must block any future public package auto-sync/auto-allow release. |
| Package risk gates | Functional local beta evidence layer | `whoathere package-risk assess`, `package-risk approve`, and `package-risk history` now provide local package memory, last-known-good selection for unpinned npm/pip/uv specs, a 7 day fresh-release cooldown, suspicious diff/reputation reason codes, and authenticated local approval receipts. `vm release-plan --state-dir <dir> --workspace <path> --package-risk-receipt` and live `vm detonate --sync-back --package-risk-receipt` use receipt-backed scanner, freshness, diff, class, artifact-review, workspace-binding, and state-local auth gates. These gates do not prove packages safe, do not bypass the VM, and do not allow native/binary/direct/VCS/editable artifacts to auto-sync. |
| Packaging/onboarding | Release-candidate implemented | [macOS local-first preview runbook](macos-local-first-preview-runbook.md) now documents first-run build, signing, VM init, provisioning, health, detonation validation, limitations, cleanup, the repeatable preview tarball script, notary credential setup, and notarization. The package script builds the release CLI/helper, signs them, runs local gates, writes a checksum, and smoke-tests the extracted archive before reporting success. `scripts/whoathere-notarize-macos-release.sh` verifies a packaged artifact, builds a notary zip, submits only when Developer ID signatures and notary credentials are configured, and writes a sanitized notarization receipt after Apple returns `Accepted`. |
| Clean install qualification | Implemented for current package | `scripts/whoathere-clean-install-qualification.sh` now validates the packaged artifact from a fresh temporary `HOME`, minimal `PATH`, user-level install prefix, empty VM state, and installed wrapper only. On this host no autonomous clean macOS VM driver was available, so the harness records `clean_vm_driver=not_available_orb_linux_only` and uses the clean-room fallback. The current Developer ID signed archive is notarized and the corrected harness verifies the Accepted notarization receipt against the archive, CLI, and helper digests. |
| Same-host runtime qualification | Implemented for current package | `scripts/whoathere-runtime-qualification.sh` validates the notarized package on the physical Apple Silicon host using the installed wrapper only, a clean temporary `HOME`, minimal `PATH`, and the qualified VM state. It starts the VM, proves guest health/toolchains, runs packaged project/npm/uv/fixture detonation validators, proves clean sync-back and malicious no-sync behavior, suspends the VM, verifies the shutdown receipt, and writes a runtime qualification receipt bound to the archive, CLI, helper, guest provisioning, release-validation, sync-validation, and shutdown receipt digests. |
| Comparator/red-team gate | Implemented for fixture-safe local gate | `whoathere vm red-team-gate` now runs 18 deterministic local cases covering static lifecycle/PEP 517 signals, dynamic npm/PyPI exfiltration shapes, DNS/HTTPS exfiltration, delayed CI activation, native/platform/direct-source risk, stale/wrong-context evidence, and raw-material rejection. It uses comparator labels for GuardDog/OpenSSF Package Analysis-style coverage without requiring public network or external scanner binaries. |

## Current Verdict

WhoaThere now has a machine-verifiable release-candidate gate for the macOS-only local-first preview.

The current release claim remains intentionally narrow: VM-backed detonation/admission evidence for
local pip projects, local-only requirements, local no-external-dependency npm install/ci projects,
and local `uv pip install .` projects. Public package resolution, `npx`/`npm exec`, `uv sync`,
native/binary/direct/VCS/editable artifacts and runtime app protection remain fail-closed or
deferred. Release readiness is proven only when `doctor --json` sees current guest provisioning,
current authenticated live npm/uv release-validation proof, current authenticated sync-validation
proof, and an authenticated Apple-accepted Developer ID notarization receipt for the packaged
artifact. Clean-install qualification also
requires the release-engineering harness to validate the installed wrapper from a clean temporary
home and bind the accepted notarization receipt to the archive, CLI, and helper digests.
Same-host runtime qualification additionally requires the installed-wrapper harness to prove live
VM health, claimed detonation workflows, sync-back/no-sync behavior, final doctor readiness, and a
verified stopped VM shutdown receipt.

## Machine-Readable Gate

`whoathere doctor --json` now includes:

- `guest_provisioning`
- `runtime_shutdown`
- `release_validation`
- `sync_validation`
- `release_notarization`
- `guest_reprovision_command`
- `release_readiness_schema`
- `release_stage`
- `release_ready`
- `release_blocking_reason_codes`
- `package_acquisition_policy`
- `package_memory_ready`
- `package_risk_gate_ready`
- `package_age_gate_days`
- `package_diff_supported`
- `package_reputation_support`
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

For this checkpoint, `release_ready` may be `true` only when guest provisioning, live npm/uv
validation, sync-validation, and notarization receipts are all present, current where required,
state-authenticated, and clean. Missing, unsigned, stale, rejected, or non-Developer-ID
notarization evidence keeps
`release_signature_notarization_not_complete` in `release_blocking_reason_codes`.

The `runtime_shutdown` object summarizes the last VM stop proof, if present. For this
detonation/admission-only preview, `stop_method=force_stop` is acceptable only when the shutdown
receipt reports `status=ok`, `high_risk_package_execution_enabled=false`, runtime health is stopped
or fail-closed, and sync-back remains disabled. `guest_requested_stop` remains preferred, and any
future sync-back or persistent guest-state claim must revisit this decision.

The `release_validation` object is written by
`whoathere/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh` only after the live npm
and uv fixture cases pass, canary output remains sanitized, host project mutation checks pass, and
public resolver/`uv sync` cases remain fail-closed before helper execution. `doctor` accepts npm and
uv release proof only when that receipt uses schema
`whoathere.macos_vm.release_validation.v1`, records disabled host execution/sync/high-risk states,
uses `package_acquisition_policy=local_only_no_public_resolver`, has a current state-local
`receipt_auth` tag, and binds to the SHA-256 digest of the current guest-provisioning receipt.
Missing, unsigned, stale, or mismatched receipts keep
`release_npm_vm_detonation_not_verified` and `release_uv_vm_detonation_not_verified` in
`release_blocking_reason_codes`.

The `release_notarization` object is written by `scripts/whoathere-notarize-macos-release.sh` only
after `xcrun notarytool submit --wait` returns `Accepted` for a Developer ID signed package. It
records the packaged artifact name, archive SHA-256, notary zip SHA-256, packaged CLI SHA-256,
packaged helper SHA-256, Apple notary submission ID, signature kinds for the CLI and helper, and
the fact that archive stapling is unsupported. `doctor` clears
`release_signature_notarization_not_complete` only when that receipt uses schema
`whoathere.macos_vm.release_notarization.v1`, records `notarytool_status=Accepted`, includes a
notary submission ID, has a state-local `receipt_auth` tag, proves both packaged binaries used
`developer_id_application` signatures, and matches the digest of the running CLI plus the configured
VM helper. An unsigned receipt, a stale receipt for an older package, or a receipt used with a
different helper remains fail-closed.

The `guest_provisioning` object now includes `agent_sha256`, `agent_source_sha256`, and
`current_agent_source_sha256` when a helper path can resolve the local helper root. Missing or
mismatched source digests add `macos_vm_guest_agent_source_digest_missing` or
`macos_vm_guest_agent_source_digest_mismatch`, force `guest_reprovision_required=true`, and keep
release validation blocked. This prevents an old installed guest agent from authorizing npm/uv
release proof after local guest-agent source changes.

## Validation Evidence For This Checkpoint

Passed for this release-readiness slice on 2026-06-27:

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
rg -n "[^[:ascii:]]" docs/whoathere/product-build-run/macos-local-release-readiness.md whoathere/crates/whoathere-cli/src/lib.rs whoathere/crates/whoathere-macos-vm/src/lib.rs
rg -n "[^[:ascii:]]" scripts/whoathere-package-macos-preview.sh docs/whoathere/product-build-run/macos-local-first-preview-runbook.md docs/whoathere/product-build-run/macos-local-release-readiness.md
cargo run --quiet --manifest-path whoathere/Cargo.toml --bin whoathere -- doctor --json
cargo run --quiet --manifest-path whoathere/Cargo.toml --bin whoathere -- doctor --json --state-dir /private/tmp/whoathere-doctor-state
cargo run --quiet --manifest-path whoathere/Cargo.toml --bin whoathere -- vm red-team-gate --json
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli vm_detonate_npm_project
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli vm_detonate_uv
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli runtime_shutdown
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
sh -n whoathere/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh
sh -n scripts/whoathere-package-macos-preview.sh
sh -n scripts/whoathere-notarize-macos-release.sh
whoathere/target/debug/whoathere vm reprovision --preflight --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
# expected exit 64 when not run as root; proves the wrapper does not cross the admin boundary
whoathere/target/debug/whoathere vm reprovision --execute --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
whoathere/target/debug/whoathere vm validate-npm-uv --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
# expected exit 64 until guest provisioning proves Node/npm and uv
whoathere/target/debug/whoathere vm validate-npm-uv --execute --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh --preflight /Users/jdc/.whoathere/macos-vm-validation
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli release_validation
scripts/whoathere-package-macos-preview.sh
WHOATHERE_VM_HEALTH_INTERVAL_SECONDS=1 WHOATHERE_VM_HEALTH_ATTEMPTS=1 whoathere/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh
scripts/whoathere-notarize-macos-release.sh --dry-run dist/whoathere-macos-arm64-preview-<git-short-sha>.tar.gz
# expected exit 64 before notarytool submission because the local preview uses ad-hoc signatures
scripts/whoathere-notarize-macos-release.sh --submit dist/whoathere-macos-arm64-preview-<git-short-sha>.tar.gz
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -fsyntax-only whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
```

Additional Goal 2 Track 1 clean-install qualification evidence on 2026-06-27:

```sh
WHOATHERE_CODESIGN_IDENTITY="Developer ID Application: Jonathan Cooper (U7BVS8X483)" scripts/whoathere-package-macos-preview.sh
scripts/whoathere-clean-install-qualification.sh --archive dist/whoathere-macos-arm64-preview-479e207.tar.gz
WHOATHERE_NOTARY_PROFILE=whoathere-notary scripts/whoathere-notarize-macos-release.sh --submit dist/whoathere-macos-arm64-preview-479e207.tar.gz
scripts/whoathere-clean-install-qualification.sh --archive dist/whoathere-macos-arm64-preview-479e207.tar.gz
```

The first clean-install harness version used `spctl -t execute` against a bare CLI Mach-O and
reported this false-negative blocker:

```text
rejected (the code is valid but does not seem to be an app)
origin=Developer ID Application: Jonathan Cooper (U7BVS8X483)
qualification_failed=spctl_cli_rejected
```

That assessment mode is app-bundle oriented and is not the correct release gate for this tar/zip
CLI distribution. The harness was corrected to require strict `codesign` verification plus an
Accepted Apple notarization receipt bound to the archive, CLI, and helper digests. Apple accepted
the notarization submission for the current package:

```text
notarization_result=/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-479e207-notarization.zip.notarytool.json
notarization_receipt=/Users/jdc/.whoathere/macos-vm-validation/bundle/release-notarization.json
notarization_receipt_written=true
notarization_status=submitted
notarytool_status=Accepted
```

After the correction, the full clean-install harness passes for the current package and writes an
ignored receipt with `qualified=true`, `partial_clean_room_qualified=true`,
`notarization_verified=true`, `cli_signature_kind=developer_id_application`,
`helper_signature_kind=developer_id_application`, `clean_vm_driver=not_available_orb_linux_only`,
`doctor_fail_closed_without_vm_state=true`, `shim_install_verified=true`, and
`sync_back_dry_run_verified=true`. This proves installed product behavior under a clean temporary
home. It still does not prove full VM-backed detonation, which remains the same-host runtime
qualification track.

Additional focused validation for the current guest-agent freshness and uv offline-install slice on
2026-06-27:

```sh
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli guest_agent_source_digest -- --nocapture
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli guest_provisioning -- --nocapture
sh -n whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -fsyntax-only whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
whoathere/target/debug/whoathere doctor --json --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
whoathere/target/debug/whoathere vm validate-npm-uv --execute --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
whoathere/target/debug/whoathere vm reprovision --preflight --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper
```

The rebuilt `doctor --json` output for the actual validation VM reported Node/npm and uv installed
in the previous root-owned provisioning receipt, but also reported
`macos_vm_guest_agent_source_digest_missing` because that older receipt did not bind the installed
guest agent to the current source digest
`sha256:28d11a41fe389e72cd89dbc1b9241646ee898dd10fdbd88f2d84dccfb742f043`.
As intended, this produced `guest_reprovision_required=true`,
`guest_reprovision_admin_required=true`, and release blockers for the stale guest agent plus npm/uv
release validation. `whoathere vm validate-npm-uv --execute` exited 64 before VM start with
`guest_tooling_not_ready_for_npm_uv_validation=true`, printed sanitized provisioning preflight
evidence, and printed this interactive admin command:

```sh
sudo WHOATHERE_NODE_RUNTIME_DIR='/Users/jdc/.nvm/versions/node/v22.22.3' WHOATHERE_UV_BINARY='/Users/jdc/.local/bin/uv' '/Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh' '/Users/jdc/.whoathere/macos-vm-validation'
```

`scripts/whoathere-package-macos-preview.sh` passed for this slice. The package script ran the full
Rust test suite, clippy with `-D warnings`, release CLI build, Swift helper tests/build, local code
signing, the fixture-safe red-team gate, archive checksum verification, and extracted package smoke
tests. The package name is derived from the current git short SHA and should be regenerated after
any later commit:

```text
package_created=/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-<git-short-sha>.tar.gz
checksum_created=/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-<git-short-sha>.tar.gz.sha256
notarization_status=not_performed
```

Additional focused validation for the user-level installer and committed preview package slice on
2026-06-27:

```sh
sh -n scripts/whoathere-install-macos-preview.sh
sh -n scripts/whoathere-package-macos-preview.sh
rg -n "[^[:ascii:]]" scripts/whoathere-install-macos-preview.sh scripts/whoathere-package-macos-preview.sh docs/whoathere/product-build-run/macos-local-first-preview-runbook.md docs/whoathere/product-build-run/macos-local-release-readiness.md
git diff --check
scripts/whoathere-package-macos-preview.sh
scripts/whoathere-notarize-macos-release.sh --dry-run dist/whoathere-macos-arm64-preview-c4ee161.tar.gz
# expected exit 64 before notarytool submission because the package uses ad-hoc local signatures
scripts/whoathere-notarize-macos-release.sh --submit dist/whoathere-macos-arm64-preview-c4ee161.tar.gz
```

The committed preview package for installer commit `c4ee161` produced:

```text
package_created=/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-c4ee161.tar.gz
checksum_created=/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-c4ee161.tar.gz.sha256
notarization_status=not_performed
```

The package smoke now proves the extracted installer can run in dry-run mode, install into a
temporary user prefix whose path contains both a space and an apostrophe, execute the installed
`bin/whoathere` wrapper, and run `doctor --json` with `WHOATHERE_MACOS_VM_HELPER` pointing at the
installed helper. The installed doctor smoke still reports `release_ready=false`; it does not
silently convert a successful install into a release-readiness claim.

The notarization dry run for `dist/whoathere-macos-arm64-preview-c4ee161.tar.gz` exited 0 after
checksum and packaged codesign verification, wrote
`dist/whoathere-macos-arm64-preview-c4ee161-notarization.zip`, and reported
`cli_signature_kind=adhoc`, `helper_signature_kind=adhoc`,
`notary_credentials_configured=false`, and `notarization_submit_ready=false`. Submit mode exited 64
with `notarization_blocker=adhoc_signature_present`, before any `xcrun notarytool` submission. This
keeps `release_signature_notarization_not_complete` as a real remaining release blocker.

The `doctor --json` smokes reported `release_ready=false`, `high_risk_allowed=false`, the inspected VM state directory, `package_acquisition_policy=local_only_no_public_resolver`, implemented pip/local detonation workflows, fail-closed npm/uv/public-resolution workflows, and release blockers for npm guest tooling/proof, uv guest tooling/proof, sync validation, and signature/notarization. While the VM was running with host and guest health proofs, doctor reported `vm_lifecycle_ready=true`, `vm_runtime_ready=true`, and `vm_reason_codes=[]`; after suspend, doctor reported `vm_lifecycle_ready=true`, `vm_runtime_ready=false`, and `vm_reason_codes=["macos_vm_runtime_not_verified"]`, while `release_blocking_reason_codes` no longer included `macos_vm_runtime_not_verified`. Sync-back readiness is reported through `sync_validation` and `release_sync_back_validation_not_verified`. Scanner availability is reported with `scanner_release_blocking=false` and `scanner_release_scope=advisory_for_local_beta_required_before_public_package_auto_sync`. Focused unit tests verify `guest_reprovision_command` is emitted from a package-shaped helper layout when the guest provisioning receipt is missing, that helper-derived lifecycle/runtime health removes stale marker-based VM blockers, and that stopped runtime state stays visible without blocking release readiness.

The red-team fixture gate passed with `passed=true`, `case_count=18`, `public_network_used=false`, and `external_scanners_required=false`. The gate does not execute arbitrary packages and does not replace scanner adapters; it proves the local fixture-safe static/dynamic evidence paths and binding checks catch or reject representative attack shapes without leaking canaries or local paths.

The npm local project planner tests passed for a no-dependency local package, helper payload forwarding, and public dependency fail-closed behavior. The uv local project planner tests passed for `uv pip install .`, helper payload forwarding, and `uv sync` fail-closed behavior. The helper build/tests and guest C syntax check passed after enabling npm and uv project payload handling. This proves host-side npm/uv project preparation and guest request plumbing, not live npm/uv execution; live npm/uv remains blocked until Node/npm and uv are provisioned and the validation VM returns clean guest evidence.

The live validation VM smoke now reports `manifest_present=true`, `manifest_valid=true`, and `manifest_path=/Users/jdc/.whoathere/macos-vm-validation/bundle/image.manifest`; it no longer reports `macos_vm_image_manifest_missing` or `macos_vm_manifest_signature_not_verified` for the prepared validation state directory. The existing validation bundle was explicitly upgraded with `whoathere vm upgrade-local-manifest --execute`, which rewrote only the legacy helper-created `signature_status=signature_verification_not_implemented` marker to `local_developer_verified` after bundle validation. Newly helper-created preview manifests use `signature_status=local_developer_verified` for local lifecycle gating. This does not satisfy the final `release_signature_notarization_not_complete` release blocker.

Text-mode `whoathere doctor` and `whoathere vm status` now keep helper output concise for normal
operator use. Short helper diagnostics are still shown, but long nested helper payloads are replaced
with byte counts and `helper_stdout=omitted_long_payload`; `--json` remains the detailed
machine-readable evidence path.

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

The helper lifecycle smoke showed that `swift build` replaces the signed helper binary, so the helper must be re-signed before VM start. After re-signing, start returned `exit_code=0`, health returned `guest_health_proven=true`, `guest_toolchain_python3_available=true`, `guest_toolchain_pip_available=true`, `guest_toolchain_npm_available=false`, and `guest_toolchain_uv_available=false`. Updated suspend behavior returned `exit_code=0`, `runtime_stop_observed=true`, and `suspend_semantics=force_stop`. Final health returned fail-closed with `runtime_process_not_running`, confirming the VM was stopped. Current `vm status` and `doctor` output report `runtime_shutdown.stop_method=force_stop`, `runtime_shutdown.reason_codes=["guest_stop_timeout"]`, `runtime_shutdown.high_risk_package_execution_enabled=false`, and `runtime_shutdown.receipt_acceptable_for_no_sync_preview=true`. This is acceptable for the current no-sync detonation preview because no guest filesystem changes are trusted or copied back to the host; it is not acceptable evidence for a future sync-back release without a new whitelist and validation pass.

Offline provisioning now supports copying host or repo-provided Node/npm and uv tooling into the
guest under `/usr/local/whoathere`. The guest agent uses a fixed WhoaThere-owned PATH for tool
discovery and detonation. The `whoathere vm reprovision` CLI wrapper now prints the exact admin
command by default and runs a non-mutating `--preflight` that checks the stopped VM disk, guest
agent source, Python/wheel sources, Node/npm source, and uv source before the operator enters an
admin password. Static validation passed, but live npm/uv proof is still pending because the emitted
`sudo ... provision-guest-readiness.sh /Users/jdc/.whoathere/macos-vm-validation` command requires
an interactive sudo password in this environment.

The provisioning and project validation scripts now emit a concrete machine-specific reprovision
command when root-owned guest tooling is missing or stale. The npm/uv validation script also prints
the provisioning preflight output before exiting on stale tooling, so missing tool sources or a
still-running VM are visible before the admin step. `vm status` and `doctor` also report
`guest_reprovision_required`, `guest_reprovision_admin_required`, and
`guest_reprovision_operator_action`, so the admin boundary is explicit rather than hidden in a
failing install path. On this workstation the non-root smoke printed
`WHOATHERE_NODE_RUNTIME_DIR=/Users/jdc/.nvm/versions/node/v22.22.3` and
`WHOATHERE_UV_BINARY=/Users/jdc/.local/bin/uv` in the suggested `sudo` command. A non-interactive
attempt to run that command failed before mutation because sudo required a terminal/password:
`sudo: a terminal is required to read the password`.

The new `whoathere vm reprovision --preflight` path and the underlying script preflight both passed
on the current validation VM state with
`ready_for_sudo_provisioning=true`, `disk_image_present=true`, `vm_runtime_running=false`,
`python_runtime_source_ready=true`, `python_wheels_source_ready=true`,
`wheel_package_source_ready=true`, `node_runtime_source_ready=true`, and
`uv_binary_source_ready=true`. This proves the next interactive sudo step has the required local
tooling inputs available; it does not replace the admin provisioning receipt or live npm/uv VM
validation.

The `whoathere vm reprovision` dry run now prints the same detected `sudo ... provision-guest-readiness.sh ...`
command that `doctor` reports. A non-root `whoathere vm reprovision --execute` smoke exited 64 with
`admin_required=true`, `reason_code=guest_readiness_provisioning_requires_root_owned_launchdaemon`,
`mutation=false`, and the same rerun command, proving the CLI wrapper does not silently try to cross
the admin boundary or mutate the VM without an interactive privileged operator action.

The new `whoathere vm validate-npm-uv` wrapper prints the post-provision execute command by default
and delegates to `validate-npm-uv-detonation.sh` only with `--execute`. On the current stale
validation VM, the wrapper exits 64 before VM start with
`guest_tooling_not_ready_for_npm_uv_validation=true`, the provisioning preflight output, and
`mutation=false`, without dumping the full doctor/helper JSON into the common stale-tooling failure
path. This keeps npm/uv release proof fail-closed while making the post-provision gate a normal CLI
workflow.

The preview packaging path now has `scripts/whoathere-package-macos-preview.sh`. It validates the
Rust workspace, builds the release CLI, locally signs the CLI, runs Swift helper tests, builds and
signs the release helper, runs the local red-team fixture gate, stages helper scripts and docs, and
writes a tarball plus SHA-256 checksum under ignored `dist/`. It deliberately reports
`notarization_status=not_performed`; final Developer ID/notarization work remains open.

The release notarization-prep path now has `scripts/whoathere-notarize-macos-release.sh`. In dry-run
mode it verifies the package checksum sidecar, extracts the archive, verifies CLI/helper codesign
state, checks the packaged npm/uv validator is executable and shell-syntax-clean, writes a
notarization zip, reports signature kinds, and reports whether notary credentials are configured.
Submit-readiness now requires both packaged binaries to report
`developer_id_application`; ad-hoc, Apple Development, and unknown signatures remain diagnostics
only. On the current local preview archive it produced
`dist/whoathere-macos-arm64-preview-<git-short-sha>-notarization.zip` and correctly reported
`cli_signature_kind=adhoc`, `helper_signature_kind=adhoc`, `cli_signature_adhoc=true`,
`helper_signature_adhoc=true`, `notary_credentials_configured=false`, and
`notarization_submit_ready=false`. A submit-mode guard smoke on the same archive exited 64 with
`notarization_blocker=adhoc_signature_present`, before any `xcrun notarytool` submission.
Submission mode rejects ad-hoc signatures, non-Developer-ID signatures, or missing credentials
before calling `xcrun notarytool`, so the final
`release_signature_notarization_not_complete` blocker remains honest until a Developer ID signed
artifact is accepted by Apple notarization.

The packaging smoke now explicitly checks that the packaged `doctor --json` output includes the
`runtime_shutdown` and `release_validation` objects,
`package_acquisition_policy=local_only_no_public_resolver`, the detonation/admission-only release
claim, and fail-closed npm/uv release blockers when no current release-validation receipt exists. It
also checks the packaged `install-macos-preview.sh` user-level installer in dry-run and execute
mode against a temporary prefix, then verifies the installed `bin/whoathere` wrapper can run
`doctor --json` with the installed helper path supplied through `WHOATHERE_MACOS_VM_HELPER`.
For a fresh package-smoke VM state, it also verifies `runtime_shutdown.receipt_present=false` and
`runtime_shutdown.receipt_acceptable_for_no_sync_preview=false`, so a missing shutdown receipt is
not silently treated as successful VM stop proof. This prevents a preview artifact with an empty VM
state from overclaiming npm/uv readiness or VM shutdown evidence.

The packaging script was rerun after the release-validation and runtime-shutdown gate changes and
produced `dist/whoathere-macos-arm64-preview-<git-short-sha>.tar.gz` plus a checksum. The checksum
verified from the extracted archive smoke, packaged `bin/whoathere --help` worked, both packaged
binaries passed `codesign --verify --strict --verbose=2`, and packaged `doctor --json` failed
closed against an empty temporary VM state directory while emitting a package-local
`guest_reprovision_command`,
`guest_reprovision_operator_action=run_guest_reprovision_command_in_interactive_admin_terminal`,
the `runtime_shutdown` and `release_validation` receipt gates, and npm/uv release blockers. Those
extracted-artifact checks are now part of `scripts/whoathere-package-macos-preview.sh`, so future
preview packages must pass the same smoke before the script reports success. The package smoke also
verifies that the extracted npm/uv detonation validator is executable, the extracted provisioning
script passes shell syntax validation, the packaged provisioning preflight fails closed on a fresh
empty package-smoke state before any admin mutation, and the packaged `bin/whoathere vm reprovision
--preflight` wrapper reports the same fail-closed preflight state. It also verifies the packaged
`bin/whoathere vm validate-npm-uv --execute` wrapper fails closed on the empty package-smoke state
before any VM start or npm/uv release claim.

The latest npm/uv planner slices changed host planner, Swift helper, and guest-agent behavior. They were validated with unit tests, helper build/tests, guest C syntax checks, and live `doctor` fail-closed readiness output. Live npm/uv detonation is still not claimed because the stopped validation VM must first be reprovisioned with the current guest agent through the interactive sudo step above, then the live npm/uv validator must pass.

The detonation execution path now performs a guest-tooling preflight before helper invocation. Dry
runs still produce mirror and project plans without requiring a VM receipt. For `--execute`, npm
requires Node/npm proof; pip requires Python and pip wheel proof; uv requires uv plus the Python and
pip wheel proof used by the guest probes. All three also require safety fields proving high-risk
execution, host home mounts, and host secret mounts are disabled. When a helper path resolves the
local helper root, the provisioning receipt must also bind the installed guest agent to the current
guest-agent source digest. On the current validation VM, Node/npm and uv are installed in the old
receipt, but the receipt predates the source-digest field and therefore returns
`macos_vm_guest_agent_source_digest_missing`.

The post-provision npm/uv release gate now lives behind
`whoathere vm validate-npm-uv --execute`, which delegates to
`whoathere/helpers/macos-vm-helper/scripts/validate-npm-uv-detonation.sh`. It checks the
provisioning receipt before VM start, starts the VM only when the receipt is ready, requires live
guest health to prove `python3`, `pip`, `npm`, and `uv`, runs clean local npm install/ci and uv pip
project cases, runs canary-reading npm lifecycle/API-use and uv import-time cases, verifies public npm/uv
resolution and `uv sync` remain fail-closed before helper execution, rejects raw canary value
leakage, checks the host project was not mutated, writes
`<state-dir>/bundle/release-validation.json` after success, signs it through
`whoathere vm attest-receipt`, and suspends the VM if it started it. In
the current validation state it exits with `guest_tooling_not_ready_for_npm_uv_validation=true`,
prints the provisioning preflight output, and prints the exact
`sudo ... provision-guest-readiness.sh ...` command before starting the VM. The focused
release-validation unit tests prove `doctor` removes the npm/uv release blockers only for a receipt
with current state-local auth bound to the current guest-provisioning digest, and rejects unsigned
or stale-digest receipts with fail-closed reason codes.

## Next Recommended Slice

Focus on live VM validation and packaging UX before expanding package-manager coverage:

1. Reprovision the stopped validation VM with the exact `sudo ... provision-guest-readiness.sh ...` command emitted by `doctor`, `provision-guest-readiness.sh`, or `validate-npm-uv-detonation.sh`, then rerun status and health to prove the receipt includes `agent_source_sha256`, has no guest provisioning reason codes, and the live guest reports `guest_toolchain_npm_available=true` and `guest_toolchain_uv_available=true`.
2. Run `whoathere/target/debug/whoathere vm validate-npm-uv --execute --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/release/whoathere-macos-vm-helper`. Keep npm/uv release claims fail-closed until that live gate passes.
3. Exercise `scripts/whoathere-package-macos-preview.sh` as the release candidate build path, then add Developer ID signing/notarization or keep the artifact clearly labeled as a local preview.
4. Run at least one supported clean `--sync-back` workflow and require a current `sync-validation.json` receipt before claiming sync-back readiness.
5. Keep force-stop behavior visible in `runtime_shutdown`; do not use shutdown state as sync-back authorization.
6. Make remaining failure messages actionable without exposing secrets or raw guest output.
7. Run `whoathere vm red-team-gate --json` on every release candidate and keep the macOS local-first preview runbook updated as npm/uv, sync-back, scanner, and packaging claims change.

After that, run live npm and uv VM detonation for no-external-dependency local projects. If either cannot be made reliable without extra guest provisioning, keep that workflow explicitly fail-closed and document the blocker instead of expanding the release claim.
