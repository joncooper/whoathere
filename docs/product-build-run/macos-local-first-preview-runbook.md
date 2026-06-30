# WhoaThere macOS Local-First Preview Runbook

## Purpose

This runbook is the operator-facing path for the Apple Silicon macOS local-first preview release.
It is intentionally narrower than the enterprise WhoaThere vision: no Vault dependency, no AWS,
no Windows, no Linux release claim, and no public package resolver fallback.

The current usable claim is:

- Python local project and local-only requirements detonation can run inside a macOS guest VM.
- Host package-manager execution remains disabled for high-risk workflows.
- Host secrets are not mirrored into the VM.
- npm has a narrow local no-external-dependency project planner, but live npm remains fail-closed
  until Node/npm are provisioned into the validation VM and live fixture/project checks pass.
- uv has a narrow local `uv pip install` project planner, but live uv remains fail-closed until uv
  is provisioned into the validation VM and live fixture/project checks pass. `uv sync` remains
  deferred until lock/source policy is explicit.
- Sync-back is an explicit beta path. It requires `--sync-back`, clean VM evidence, a package-risk
  receipt bound to the same workspace digest, clean scanner/diff/freshness evidence, a bounded
  guest output archive, a deny-by-default host allowlist, and a current `sync-validation.json`
  receipt. Unsupported, suspicious, native, binary, direct/VCS/editable, traversal, symlink,
  canary, or network-signaling outputs sync nothing.
- Package acquisition is local-only for this preview: `doctor` reports
  `package_acquisition_policy=local_only_no_public_resolver`. Public npm/PyPI resolution remains
  fail-closed unless a separate VM-only resolver policy is implemented and tested.

## Prerequisites

- Apple Silicon macOS host.
- Xcode command line tools.
- Rust toolchain.
- Swift Package Manager.
- At least 64 GiB disk space for the VM bundle and cache.
- 6 GiB RAM available for normal VM validation; 8 GiB is preferred for native/deep tests.
- A macOS restore IPSW, or explicit approval to fetch Apple's latest supported restore image.
- Interactive `sudo` for one stopped-VM guest provisioning step.

Optional, for npm and uv validation:

- A host Node/npm runtime that can be copied into the VM.
- A host uv binary that can be copied into the VM.

The current validation host paths are:

```sh
export WHOATHERE_NODE_RUNTIME_DIR=/Users/jdc/.nvm/versions/node/v22.22.3
export WHOATHERE_UV_BINARY=/Users/jdc/.local/bin/uv
```

## Build

From the repo root:

```sh
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli --bin whoathere
```

Build and sign the macOS VM helper:

```sh
cd /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper
swift test
swift build
./scripts/sign-local-helper.sh
```

Run `./scripts/sign-local-helper.sh` after every `swift build`; SwiftPM replaces the signed helper
binary.

Useful shell variables:

```sh
export WHOATHERE=/Users/jdc/src/whoathere/whoathere/target/debug/whoathere
export WHOATHERE_STATE=/Users/jdc/.whoathere/macos-vm-validation
export WHOATHERE_HELPER=/Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
```

## Scanner Setup

Scanners add useful signals about known vulnerabilities, suspicious package behavior, SBOM
contents, and repository quality. They do not replace the macOS VM and they cannot authorize
package execution or file copy-back by themselves.

Bootstrap or locate scanners from the repo root:

```sh
scripts/whoathere-bootstrap-scanners.sh
```

The bootstrap script prefers the ignored local cache at `.whoathere/scanners/`, may use Homebrew,
`uv tool`, `uvx`, or GitHub release downloads, and writes:

```text
.whoathere/scanners/scanner-bootstrap.json
```

Inspect scanner readiness:

```sh
$WHOATHERE scanners list --json
$WHOATHERE scanners bootstrap-plan --json
```

Run scanner evidence against a workspace:

```sh
$WHOATHERE scanners run --workspace /path/to/project --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" --execute --json
```

The output uses schema `whoathere.external_scanner_run.v1`. It reports normalized scanner status,
finding counts where cheaply available, stdout/stderr digests, and reason codes. It does not include
raw scanner output, package contents, tokens, canaries, or raw host secret paths.
For CLI use, read `scanner_clean`, `decision_summary`, `host_effect`, and `recommended_actions`
first. Scanner execution may spawn trusted host scanner tools, but it does not run npm, pip, or uv
install commands and does not intentionally execute package code.
When `--state-dir` is provided, executed scanner receipts include a state-local
`scanner_receipt_auth` tag and executable digests. Clean scanner receipts without that auth tag are
report-only and cannot satisfy package-risk auto-sync evidence.
Package-risk also rejects clean scanner receipts that were only dry-run, target a different
workspace digest, omit expected core scanner records, contain malformed executable digests, report an
inconsistent runnable core scanner count, or show no core scanner actually passed.

For the current local-only beta, scanner availability and bootstrap receipt validity are visible in
`doctor --json`, but remain advisory: `scanner_release_blocking=false`. Future public-package
auto-trust requires all core scanners plus a valid, current bootstrap receipt. Missing scanners,
malformed bootstrap receipts, or stale scanner version records must block future public-package
auto-trust, but they do not block the current local-only VM beta because public package acquisition
is still disabled.

Run the deterministic scanner contract smoke:

```sh
scripts/whoathere-scanner-integration-smoke.sh
```

To add a best-effort real-tool pass after bootstrap:

```sh
WHOATHERE_SCANNER_REAL_SMOKE=1 scripts/whoathere-scanner-integration-smoke.sh
```

By default, scanner binaries are loaded from `$HOME/.whoathere/scanners/bin` or trusted system
binary directories. The scanner cache can be overridden for deterministic tests with
`WHOATHERE_SCANNER_CACHE_DIR=/path/to/cache`, but scanner binaries inside the assessed workspace are
refused.

## Package Risk Gates

Package risk gates remember local package decisions and help avoid surprise upgrades. They are
still evidence, not a proof that a package is safe.

Assess a workspace:

```sh
$WHOATHERE scanners run --workspace /path/to/project --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" --execute --json > scanner-receipt.json
$WHOATHERE package-risk assess --workspace /path/to/project --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" --scanner-receipt scanner-receipt.json --json
```

The assessment writes an append-only local evidence store under:

```text
$WHOATHERE_STATE/package-risk/package-risk-evidence.jsonl
```

It also writes a receipt under:

```text
$WHOATHERE_STATE/package-risk/receipts/
```

The receipt records package name, ecosystem, requested spec, selected last-known-good version when
used, source kind, artifact hash, scanner gate, freshness gate, diff gate, reputation status,
verdict, and reason codes. It does not include raw package source, scanner dumps, canaries, tokens,
or host secret paths.

For CLI use, read these fields first:

- `overall_verdict` tells whether the workspace is an `auto_sync_candidate`, needs
  `manual_review`, or is denied.
- `decision_summary` gives the same decision in plain language.
- `host_effect` states that package-risk assessment itself does not run package code on the host or
  copy project files back from the VM. It may write receipts and local package memory.
- `recommended_actions` gives the next practical command or review step.

Approve a local beta baseline:

```sh
$WHOATHERE package-risk approve --receipt /path/to/receipt.json --reason "reviewed local beta baseline" --state-dir "$WHOATHERE_STATE" --json
```

Review package history:

```sh
$WHOATHERE package-risk history --package safe-pkg --ecosystem pypi --state-dir "$WHOATHERE_STATE" --json
```

Policy for the macOS beta:

- Exact previously approved artifacts are recognized as last-known-good.
- Unpinned npm, pip, and uv specs prefer the newest locally approved version when one exists.
- Unpinned specs with no last-known-good version require manual review.
- Missing, dirty, stale, not-executed, or wrong-workspace scanner evidence requires manual review.
- Only clean auto-sync-candidate package-risk receipts can be approved into last-known-good memory.
- Fresh public package versions cannot auto-sync until the 7 day cooldown is satisfied.
- Suspicious diffs, new lifecycle scripts, `.pth` startup hooks, native/binary markers, direct URLs,
  VCS dependencies, editable installs, platform-specific payloads, and credential/network-looking
  code block auto-sync.
- Reputation is a warning/reason-code signal. It never authorizes a package by itself.

Use a package-risk receipt with the release-plan model. The receipt must be produced by
`package-risk assess` under the same WhoaThere state directory because WhoaThere verifies a
state-local receipt authentication tag before applying it:

```sh
$WHOATHERE vm release-plan --state-dir "$WHOATHERE_STATE" --workspace /path/to/project \
  --class pypi.pure_wheel.v1 \
  --vm-ready --static-clean --dynamic-clean --egress-clean --no-canary-access \
  --package-risk-receipt /path/to/package-risk-receipt.json --json
```

Use a package-risk receipt with live beta sync-back:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --package-risk-receipt /path/to/package-risk-receipt.json \
  --execute --sync-back --json pip -- install .
```

Run the deterministic package-risk and attack harnesses:

```sh
scripts/whoathere-package-risk-smoke.sh
scripts/whoathere-real-world-attack-harness.sh
scripts/whoathere-local-beta-pressure-smoke.sh
scripts/whoathere-local-beta-pressure-suite.sh
```

The local beta pressure smoke uses realistic local npm, pip, and uv project shapes without public
network access. It checks that clean pinned registry-shaped inputs can become beta sync candidates,
that npm local workspace/file dependencies remain denied, that uv range requests use the latest
approved last-known-good version, that risky `uv.lock` transitive sources are surfaced and denied,
and that package-risk output explains the host impact and next action.

The package-risk smoke also covers a maintainer-takeover style update: a clean pinned npm package is
approved as a local baseline, then a later pinned version of the same package adds a `postinstall`
network/token path. Even with clean scanner evidence, the later version must require manual review
with a suspicious-diff reason and concrete behavior reasons.

The real-world attack harness includes npm and Python fixtures for install-time hooks, startup or
import-time behavior, transitive npm lockfile entries, API-compatible credential access, delayed
CI activation, macOS-specific activation, and native/binary markers. These fixtures are
non-destructive and use mock signals only; the expected result is manual review or deny before host
package execution or unsafe sync-back.

The registry compatibility smoke uses the local loopback dev registry. It now verifies a real
`npm ci` flow from a generated lockfile, confirms lockfile integrity and loopback-only resolved
URLs, installs the npm fixture without running scripts, installs the PyPI fixture from a
hash-pinned requirements file, and confirms pip rejects a bad hash without leaving the package
installed.

The pressure suite runs the package-risk smoke, real-world attack harness, local beta pressure
smoke, and registry compatibility smoke with per-step elapsed seconds. Set
`WHOATHERE_PRESSURE_SKIP_COMPAT=1` only when loopback registry tests cannot run in the current
environment.

The pressure suite skips live VM runtime qualification by default. To include the same-host VM
detonation and sync-back/no-sync gate, provide a preview archive:

```sh
WHOATHERE_PRESSURE_ENABLE_VM=1 \
WHOATHERE_PRESSURE_RUNTIME_ARCHIVE=dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz \
scripts/whoathere-local-beta-pressure-suite.sh
```

Optionally set `WHOATHERE_PRESSURE_RUNTIME_STATE_DIR` to reuse a prepared validation VM state.

## Package A Preview Artifact

To build a repeatable Apple Silicon preview tarball with the release CLI, signed release helper,
helper scripts, a no-sudo user installer, guest readiness agent source, and local preview docs:

```sh
scripts/whoathere-package-macos-preview.sh
```

The package name is derived from the current git commit, so the script refuses a dirty worktree by
default. It also refuses `WHOATHERE_PACKAGE_SKIP_VALIDATION=true` unless
`WHOATHERE_PACKAGE_ALLOW_SKIPPED_VALIDATION=true` is set. Use that override only for non-release
developer experiments after equivalent validation has already passed.

The script runs Rust validation, builds the release CLI, locally signs the CLI, runs Swift helper
tests, builds and signs the release helper, runs the local red-team fixture gate, writes the
archive and checksum, then extracts the archive and smoke-tests the packaged CLI/helper. The smoke
verifies the checksum, `bin/whoathere --help`, packaged codesign state, the package installer,
and packaged `doctor --json` fail-closed output with a package-local guest reprovision command.
The package smoke also installs into a temporary user prefix and verifies the installed
`bin/whoathere` wrapper sets `WHOATHERE_MACOS_VM_HELPER` to the installed helper without requiring
manual `--helper` flags. The package smoke also verifies that the packaged doctor output includes
the runtime-shutdown and
release-validation gates, keeps the npm/uv release blockers present when no current validation
receipt exists, and does not treat a missing shutdown receipt in a fresh package smoke state as a
successful VM stop proof. It also syntax-checks the packaged provisioner and verifies
`provision-guest-readiness.sh --preflight` fails closed on a fresh empty package-smoke state before
any admin mutation.

```text
dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz
dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz.sha256
```

After extracting the archive, install for the current user without sudo:

```sh
./install-macos-preview.sh --prefix "$HOME/.whoathere"
export PATH="$HOME/.whoathere/bin:$PATH"
whoathere doctor --json
```

The installer copies the extracted package under `$HOME/.whoathere/releases/<package-name>` and
writes `$HOME/.whoathere/bin/whoathere` as a wrapper that points the CLI at the packaged helper. It
does not initialize or mutate the VM; use the `vm init`, `vm reprovision`, and validation commands
below for that.

Set `WHOATHERE_CODESIGN_IDENTITY` to use a non-ad-hoc signing identity. The script does not perform
Apple notarization, so final release signing/notarization remains a separate blocker.

To prepare or submit a release artifact for Apple notarization, first build the preview package with
a Developer ID signing identity, then run:

```sh
scripts/whoathere-notarize-macos-release.sh --dry-run dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz
```

The dry run verifies the checksum sidecar when present, extracts the archive, verifies CLI/helper
codesign state, checks the packaged npm/uv validator, and writes a notarization zip. It reports
`cli_signature_kind` and `helper_signature_kind`; submit-readiness requires both to be
`developer_id_application`. Ad-hoc, Apple Development, and unknown signatures are accepted only as
diagnostics and report `notarization_submit_ready=false`.

Submit only after the dry run reports Developer ID Application signed binaries and notary
credentials are configured:

```sh
scripts/whoathere-store-notary-credentials.sh
```

This prompts through `xcrun notarytool` for the Apple app-specific password and stores the
credential in macOS Keychain under the default profile `whoathere-notary`. Generate the
app-specific password from the Apple ID account page; do not store it in `.env`, shell history, or
the repository.

```sh
WHOATHERE_NOTARY_PROFILE=whoathere-notary \
  scripts/whoathere-notarize-macos-release.sh --submit dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz
```

Submit mode verifies the configured notary credentials before claiming
`notarization_submit_ready=true`. Dry-run mode reports
`notarization_submit_prerequisites_ready` for the archive/signature/configuration checks, but leaves
`notarization_submit_ready=false` until credentials have been verified in submit mode. If the
Keychain profile is missing or unusable, the script reports `notary_credentials_verified=false` and
exits with a credential blocker before attempting submission.

Alternatively set `WHOATHERE_NOTARY_APPLE_ID`, `WHOATHERE_NOTARY_TEAM_ID`, and
`WHOATHERE_NOTARY_PASSWORD` for non-interactive automation. Prefer the Keychain profile for local
release work. Zip archives are submitted for Apple notarization but are not stapled; the script
records this explicitly as `stapling_supported_for_archive=false`.

## Clean Install Qualification

Goal 2 Track 1 validates the packaged artifact as an installed user product rather than a Cargo or
Swift build tree. From the release-engineering repo root, the repeatable harness is:

```sh
scripts/whoathere-clean-install-qualification.sh --archive dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz
```

The harness uses a fresh temporary `HOME`, a minimal system `PATH`, a user-level install prefix
containing spaces and an apostrophe, an empty VM state directory, and the installed
`bin/whoathere` wrapper only. It verifies the archive checksum, package layout, helper scripts,
Developer ID signatures, an Accepted Apple notarization receipt bound to the archive/CLI/helper
digests, installer dry-run and install, installed wrapper `doctor --json`, `vm status --json`,
fail-closed reprovision and npm/uv validation paths, shim materialization for npm/npx/pip/pip3 plus
opt-in python/python3, and a dry-run `vm detonate --sync-back` command that syncs nothing without
guest evidence. It also checks that installed command output does not leak the repo path. The
harness deliberately does not use `spctl -t execute` on the bare CLI/helper Mach-O files; that
assessment mode is app-bundle oriented and can reject valid command-line tools as "not an app".

If a clean macOS VM driver is not available on the host, the harness records that gap in the
receipt and runs the clean-room fallback. This is acceptable for Track 1 install/onboarding
qualification, but it is not a substitute for full VM-backed detonation. Nested macOS VM detonation
inside a guest is not required or claimed by this track.

The receipt is written next to the archive by default:

```text
dist/whoathere-macos-arm64-preview-<git-sha>-clean-install-qualification.json
```

For diagnostic work before notarization, the harness can run the non-notarized portion:

```sh
scripts/whoathere-clean-install-qualification.sh --archive dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz --allow-unnotarized
```

That mode exits 0 only for the clean-room install checks, writes `partial_clean_room_qualified=true`,
and keeps `qualified=false`, `notarization_requirement_bypassed=true`, and
`gatekeeper_distribution_qualified=false` in the receipt. Do not use an `--allow-unnotarized`
receipt as full clean-install release evidence.

## Same-Host Runtime Qualification

Goal 2 Track 2 validates the notarized package against the physical Apple Silicon host VM runtime
using the installed wrapper only. Run it after the package is notarized and the validation VM has
been provisioned with the current guest agent and offline Python, npm, and uv tooling:

```sh
scripts/whoathere-runtime-qualification.sh --archive dist/whoathere-macos-arm64-preview-<git-sha>.tar.gz --state-dir "$WHOATHERE_STATE"
```

The harness installs the package into a temporary user prefix with a clean `HOME` and minimal
`PATH`, starts the VM, proves guest health and toolchains, runs the packaged project/npm/uv/fixture
detonation validators, exercises clean sync-back and malicious no-sync cases, explicitly suspends
the VM, verifies the shutdown receipt, and requires final `doctor --json` release readiness. It
writes a receipt next to the archive:

```text
dist/whoathere-macos-arm64-preview-<git-sha>-runtime-qualification.json
```

If guest provisioning is stale, the harness prints the exact interactive
`sudo ... provision-guest-readiness.sh` command, writes
`dist/whoathere-macos-arm64-preview-<git-sha>-runtime-reprovision.sh`, and exits before claiming
runtime qualification. Run that generated handoff script in an admin-capable terminal; it performs
the sudo provisioning step and then resumes runtime qualification for the same archive.

## Initialize Or Reuse The VM

Fetch and install Apple's latest supported restore image:

```sh
$WHOATHERE vm init --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --fetch-latest-restore-image --execute
```

Or use a local restore IPSW:

```sh
$WHOATHERE vm init --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --restore-image /absolute/path/to/macos-restore.ipsw --execute
```

Inspect status before starting:

```sh
$WHOATHERE vm status --json --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
$WHOATHERE doctor --json --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

Expected before release hardening is complete:

- `release_ready=false`
- `high_risk_allowed=false`
- Existing validation bundles created before local developer manifest verification may still report
  `macos_vm_manifest_signature_not_verified` until they are reinitialized or explicitly upgraded:

  ```sh
  $WHOATHERE vm upgrade-local-manifest --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
  ```

  The upgrade command only rewrites helper-created local preview manifests from
  `signature_verification_not_implemented` to `local_developer_verified`; malformed, non-local, or
  incomplete bundles remain fail closed. New helper-created preview bundles use
  `signature_status=local_developer_verified` for local lifecycle gating.
- scanner and packaging/red-team release blockers

## Provision Guest Readiness Tooling

The VM must be stopped for provisioning. This step is admin-only because the guest LaunchDaemon and
agent must be root-owned on the guest Data volume.

Before entering an admin password, run the non-mutating preflight:

```sh
$WHOATHERE vm reprovision --preflight --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

The preflight checks that the VM disk and guest agent source exist, the VM is stopped, and Python,
wheel, Node/npm, and uv sources are discoverable. It reports `ready_for_sudo_provisioning=true`
only when the next `sudo ... provision-guest-readiness.sh ...` command has the required local
inputs available. To print that command without running the preflight, use:

```sh
$WHOATHERE vm reprovision --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

For Python-only provisioning:

```sh
sudo /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh "$WHOATHERE_STATE"
```

For npm and uv validation, force explicit tool sources:

```sh
sudo WHOATHERE_NODE_RUNTIME_DIR="$WHOATHERE_NODE_RUNTIME_DIR" WHOATHERE_UV_BINARY="$WHOATHERE_UV_BINARY" /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh "$WHOATHERE_STATE"
```

If provisioning is missing or stale, `provision-guest-readiness.sh` and the validation scripts
emit a machine-specific `sudo ... provision-guest-readiness.sh ...` command with detected
`WHOATHERE_NODE_RUNTIME_DIR` and `WHOATHERE_UV_BINARY` values when they are available.
The npm/uv validation gate also prints the provisioning preflight output before it exits, so missing
tool sources or a still-running VM are visible before the admin step. `whoathere doctor --json` also
reports `guest_reprovision_command` when it can derive the helper script path from the configured
helper and the guest provisioning receipt is missing or stale.

Then verify the receipt and live guest state:

```sh
$WHOATHERE vm status --json --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
$WHOATHERE vm start --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
sleep 10
$WHOATHERE vm health --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

The receipt should report installed toolchains. The live health proof should report:

```text
guest_toolchain_python3_available=true
guest_toolchain_pip_available=true
guest_toolchain_npm_available=true
guest_toolchain_uv_available=true
high_risk_package_execution_enabled=false
```

If npm or uv is missing from either receipt or health output, keep npm/uv workflows unclaimed and
fail closed.

`whoathere vm detonate --execute` also checks the guest provisioning receipt before preparing a
project payload or invoking the helper. When npm, uv, or the Python/pip staging materials used by
`uv pip install` are missing, the command should fail closed with `helper=null`,
`project_payload=null`, `verdict=preflight_security_outcome`, and the matching toolchain reason code
such as `macos_vm_guest_node_runtime_not_provisioned`,
`macos_vm_guest_uv_binary_not_provisioned`, or `macos_vm_guest_pip_tooling_not_provisioned`.

## Validate Detonation

Run fixture validation:

```sh
WHOATHERE_VM_STATE_DIR="$WHOATHERE_STATE" /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/validate-detonation-fixtures.sh
WHOATHERE_VM_STATE_DIR="$WHOATHERE_STATE" /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
$WHOATHERE vm validate-npm-uv --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
```

Run a local Python project detonation:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json pip -- install .
```

Run the same workflow with beta sync-back enabled:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --package-risk-receipt /path/to/package-risk-receipt.json \
  --execute --sync-back --json pip -- install .
```

Run local-only requirements detonation:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json pip -- install -r requirements.txt
```

Run a local npm project detonation only for a package with no external dependency resolution:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/npm-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json npm -- install
```

To sync approved npm outputs, add `--sync-back` and a package-risk receipt for the same workspace.
The host accepts only `package-lock.json` and `node_modules` files that pass the sync planner.
`node_modules/.bin`, native outputs, and suspicious paths remain blocked.

This path is intentionally narrow. `package.json` dependency sections, package specs passed to
`npm install`, public registry overrides, native markers, and lockfiles that imply external
resolution remain fail-closed until a public package acquisition policy exists.

Run a local uv project detonation only through `uv pip install` and only for local/no-public
resolution projects:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute --json uv -- pip install .
```

To sync approved uv outputs, add `--sync-back` and a package-risk receipt for the same workspace.
The host accepts only project-local Python environment files under the approved `.venv/lib/...`
output shape.

`uv sync` is intentionally not a claimed live workflow yet; it remains fail-closed until lockfile
and source policy are explicit and tested.

The npm/uv validation script starts the VM when needed, requires live guest health to prove
`python3`, `pip`, `npm`, and `uv`, runs clean local npm and uv project cases, runs canary-reading
npm lifecycle/API-use and uv import-time cases, verifies public npm/uv resolution fails before
helper execution, checks `uv sync` remains deferred, and suspends the VM if it started it. If guest
tooling is missing, it prints the exact reprovision command and exits before VM start. After a
complete successful run it writes `$WHOATHERE_STATE/bundle/release-validation.json`. `doctor --json`
uses that receipt as npm/uv release proof only when it has a current state-local
`receipt_auth` tag, is bound to the current `guest-provisioning.json` SHA-256 digest, and records
disabled host execution, disabled high-risk execution, and
`package_acquisition_policy=local_only_no_public_resolver`. Present but unsigned local JSON is
reported, but it is not trusted. Missing, unsigned, stale, or mismatched release-validation
receipts keep npm/uv release blockers in place.

A successful `--sync-back` run writes `$WHOATHERE_STATE/bundle/sync-validation.json`. The command
must also receive a clean package-risk receipt from `$WHOATHERE_STATE/package-risk/receipts/` with a
receipt id, matching `workspace_sha256`, recent `created_at_unix_seconds`, clean nested
`scanner_evidence`, acceptable artifact-review status, allowed package class, clean freshness/diff
verdicts, and a valid state-local `receipt_auth` tag. `doctor --json` uses the sync-validation
receipt as sync-back release proof only when it has a current state-local `receipt_auth` tag and is
bound to the current CLI digest, current helper digest, current `guest-provisioning.json` digest,
and `whoathere.sync_policy.local_beta.v1`. Missing, unsigned, or stale sync-validation receipts keep
`release_sync_back_validation_not_verified` in place.

Unsupported or unsafe inputs must fail before helper execution, including:

- public resolver dependencies
- direct URLs
- VCS/editable dependencies
- native extensions
- binary wheels
- symlink/traversal escapes
- secret files or host credential paths

## Stop And Verify Fail-Closed State

```sh
$WHOATHERE vm suspend --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
$WHOATHERE vm health --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

Final health should fail closed with `runtime_process_not_running`.

`whoathere vm status --json` and `whoathere doctor --json` also report a `runtime_shutdown` object
when `bundle/shutdown.json` exists. `guest_requested_stop` is preferred. For beta sync-back,
readiness depends on the explicit sync-validation receipt rather than on trusting stopped guest
state after the fact.

## Release Gate

Do not call the macOS local-first preview ready until all of these are true:

- `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` passes.
- `cargo test --manifest-path whoathere/Cargo.toml` passes.
- `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` passes.
- Helper `swift test`, `swift build`, and `./scripts/sign-local-helper.sh` pass.
- Guest C compile check passes.
- Shell syntax checks for touched scripts pass.
- ASCII scan over touched docs/scripts/Rust/Swift/C files has no matches.
- `whoathere vm red-team-gate --json` passes with `passed=true`.
- `scripts/whoathere-package-risk-smoke.sh` passes.
- `scripts/whoathere-real-world-attack-harness.sh` passes.
- Live VM validation passes for every workflow claimed in the release.
- For npm/uv claims, `validate-npm-uv-detonation.sh` has written a current
  state-authenticated `release-validation.json` receipt and `doctor --json` no longer reports
  `release_npm_vm_detonation_not_verified` or `release_uv_vm_detonation_not_verified`.
- For sync-back claims, at least one supported clean `--sync-back` run has written a current
  state-authenticated `sync-validation.json` receipt and `doctor --json` no longer reports
  `release_sync_back_validation_not_verified`.
- `doctor --json` still reports `release_ready=false` until packaging, signing/notarization,
  npm/uv proof, sync-validation proof, and public package policy gates are actually complete.
- Missing scanner binaries are advisory for the local-only sync beta; they must be installed or
  otherwise replaced by explicit evidence before any public package auto-sync or auto-allow claim.
- Package-risk receipts must be state-local, authenticated, recent, and show clean freshness and
  diff gates before `vm release-plan` can model public package auto-sync eligibility.

## Limitations

- This is not a universal malware detector.
- This does not protect arbitrary runtime application behavior after a package is admitted.
- This does not safely execute arbitrary native code.
- This syncs VM outputs back to the host only through the explicit beta allowlist after clean VM
  evidence. Unsupported or suspicious outputs sync nothing.
- This does not support global/system Python installs.
- This does not claim npm or uv success until tool provisioning and live detonation pass.
- This does not use public package resolver fallback.
- This does not replace code review for API-compatible packages that add malicious behavior at
  normal runtime call sites.

## Cleanup

Stop the VM before cleanup:

```sh
$WHOATHERE vm suspend --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
```

Prune helper-managed transient state:

```sh
$WHOATHERE vm prune --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --execute
```

Remove the validation VM bundle only when you are sure you no longer need it:

```sh
rm -rf "$WHOATHERE_STATE"
```
