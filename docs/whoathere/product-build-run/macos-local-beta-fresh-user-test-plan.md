# WhoaThere macOS Local Beta Fresh-User Test Plan

This plan tests the macOS local beta from a second macOS user account on the same Apple Silicon
machine. It is a practical substitute when a separate clean Mac is not available.

## What This Proves

- The preview archive can be installed from a normal user account without Cargo, SwiftPM, or repo
  paths.
- The installed `whoathere` wrapper finds the packaged helper.
- A separate user home gets separate state, package memory, scanner receipts, and VM receipts.
- The product fails closed before VM provisioning.
- The VM can be initialized, provisioned, started, used, and suspended for that user state.
- Supported clean workflows can detonate in the VM.
- Mock malicious workflows are denied without touching the host project.
- The current release-candidate gap around release-evidence handoff is visible: a new user state
  should fail closed for copy-back until it has current release-notarization evidence.

## What This Does Not Prove

- It is not a full fresh-machine test. The host OS, kernel, firmware, Xcode Command Line Tools,
  Homebrew installation, Apple signing trust store, and network environment are shared.
- It does not prove Intel Mac support.
- It does not prove public registry mirroring, AWS Vault, enterprise policy, or runtime app
  protection.
- It does not prove nested macOS virtualization.
- It does not prove arbitrary packages are safe.

## Required Inputs

Use the current release-candidate archive:

```text
/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-a212742.tar.gz
/Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-a212742.tar.gz.sha256
```

Expected current release evidence on the build account:

- `doctor --json` reports `release_ready=true`.
- The archive has an Accepted Apple notarization receipt.
- Runtime qualification has passed for the build account's validation VM.

## Test User Choice

Create a second macOS account named `whoatherebeta`.

Recommended setup:

- Use System Settings > Users & Groups.
- Create a standard user if you want to prove admin separation.
- Keep one admin Terminal session available in the main account for the single guest provisioning
  command.

If you make `whoatherebeta` an admin user, that user can run the provisioning command directly.
The standard-user path is more conservative and better reflects user-level installation with
admin-assisted setup.

## Stage The Archive

From the main account:

```sh
mkdir -p /Users/Shared/whoathere-beta
cp /Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-a212742.tar.gz \
  /Users/Shared/whoathere-beta/
cp /Users/jdc/src/whoathere/dist/whoathere-macos-arm64-preview-a212742.tar.gz.sha256 \
  /Users/Shared/whoathere-beta/
chmod -R a+rX /Users/Shared/whoathere-beta
```

Log into the `whoatherebeta` account for the remaining steps unless a step explicitly says to use
an admin account.

## Phase 1: Install And Fail-Closed Readiness

In the `whoatherebeta` account:

```sh
cd /Users/Shared/whoathere-beta
shasum -a 256 -c whoathere-macos-arm64-preview-a212742.tar.gz.sha256
tar -xzf whoathere-macos-arm64-preview-a212742.tar.gz
cd whoathere-macos-arm64-preview-a212742
./install-macos-preview.sh --dry-run --prefix "$HOME/.whoathere"
./install-macos-preview.sh --prefix "$HOME/.whoathere"
export PATH="$HOME/.whoathere/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export WHOATHERE_STATE="$HOME/.whoathere/macos-vm-validation"
whoathere --help >/tmp/whoathere-fresh-user-help.txt
whoathere doctor --state-dir "$WHOATHERE_STATE" --json > /tmp/whoathere-fresh-user-doctor-initial.json
```

Acceptance checks:

```sh
grep -q '"command": "whoathere doctor"' /tmp/whoathere-fresh-user-doctor-initial.json
grep -q '"release_ready": false' /tmp/whoathere-fresh-user-doctor-initial.json
grep -q '"package_acquisition_policy": "local_only_no_public_resolver"' /tmp/whoathere-fresh-user-doctor-initial.json
```

Also inspect the output manually for:

- no `/Users/jdc/src/whoathere` repo path in normal installed output,
- no host secret paths,
- clear next actions.

## Phase 2: Optional Scanner Readiness

If Homebrew and uv are available to this user, install scanner tools:

```sh
brew install osv-scanner syft grype trivy scorecard
uv tool install guarddog
uv tool install pip-audit
```

Then run:

```sh
whoathere scanners list --json > /tmp/whoathere-fresh-user-scanners.json
```

Acceptance checks for full scanner readiness:

```sh
grep -q '"name": "guarddog", "available": true' /tmp/whoathere-fresh-user-scanners.json
grep -q '"name": "osv-scanner", "available": true' /tmp/whoathere-fresh-user-scanners.json
grep -q '"name": "pip-audit", "available": true' /tmp/whoathere-fresh-user-scanners.json
grep -q '"name": "syft", "available": true' /tmp/whoathere-fresh-user-scanners.json
grep -q '"name": "grype", "available": true' /tmp/whoathere-fresh-user-scanners.json
```

If scanner installation is skipped, record that copy-back eligibility was not fully tested for the
fresh user. VM detonation and deny/no-host-write tests can still run.

## Phase 3: VM Initialization

Initialize the VM for the fresh user. Use a local restore image if available:

```sh
whoathere vm init --state-dir "$WHOATHERE_STATE" \
  --restore-image /absolute/path/to/macos-restore.ipsw \
  --execute
```

Or fetch Apple's current restore image:

```sh
whoathere vm init --state-dir "$WHOATHERE_STATE" \
  --fetch-latest-restore-image \
  --execute
```

Run the preflight:

```sh
whoathere vm reprovision --preflight --state-dir "$WHOATHERE_STATE" \
  > /tmp/whoathere-fresh-user-reprovision-preflight.txt 2>&1 || true
cat /tmp/whoathere-fresh-user-reprovision-preflight.txt
```

Expected result: a printed `sudo ... provision-guest-readiness.sh ...` command.

If the fresh user is not admin, run the printed command from an admin Terminal exactly as printed.
It must point at the fresh user's installed helper and fresh user's state directory.

After provisioning, return to the fresh user account:

```sh
whoathere doctor --state-dir "$WHOATHERE_STATE" --json > /tmp/whoathere-fresh-user-doctor-provisioned.json
grep -q '"guest_reprovision_required": false' /tmp/whoathere-fresh-user-doctor-provisioned.json
```

Start and verify health:

```sh
whoathere vm start --state-dir "$WHOATHERE_STATE" --execute
whoathere vm health --state-dir "$WHOATHERE_STATE" > /tmp/whoathere-fresh-user-health.txt
grep -q 'guest_health_proven' /tmp/whoathere-fresh-user-health.txt
grep -q 'guest_toolchain_python3_available' /tmp/whoathere-fresh-user-health.txt
grep -q 'guest_toolchain_pip_available' /tmp/whoathere-fresh-user-health.txt
grep -q 'guest_toolchain_npm_available' /tmp/whoathere-fresh-user-health.txt
grep -q 'guest_toolchain_uv_available' /tmp/whoathere-fresh-user-health.txt
```

## Phase 4: Clean And Malicious Detonation

Create a clean npm project:

```sh
mkdir -p "$HOME/whoathere-fresh-smoke/npm-clean"
cd "$HOME/whoathere-fresh-smoke/npm-clean"
cat > package.json <<'JSON'
{
  "name": "whoathere-fresh-npm-clean",
  "version": "0.0.1",
  "private": true,
  "whoatherePublishedAtUnixSeconds": 1700000000,
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}
JSON
cat > postinstall.js <<'JS'
require("fs").writeFileSync("clean.marker", "ok");
JS
```

Run without copy-back:

```sh
whoathere vm detonate --workspace "$HOME/whoathere-fresh-smoke/npm-clean" \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  npm -- install > /tmp/whoathere-fresh-user-npm-clean.json
```

Acceptance checks:

```sh
grep -q '"verdict": "helper_observed_clean"' /tmp/whoathere-fresh-user-npm-clean.json
test ! -e "$HOME/whoathere-fresh-smoke/npm-clean/clean.marker"
test ! -d "$HOME/whoathere-fresh-smoke/npm-clean/node_modules"
```

Create a mock malicious npm project:

```sh
mkdir -p "$HOME/whoathere-fresh-smoke/npm-canary"
cd "$HOME/whoathere-fresh-smoke/npm-canary"
cat > package.json <<'JSON'
{
  "name": "whoathere-fresh-npm-canary",
  "version": "0.0.1",
  "private": true,
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}
JSON
cat > postinstall.js <<'JS'
const fs = require("fs");
if (process.env.NPM_TOKEN || process.env.GITHUB_TOKEN) {
  fs.writeFileSync("canary-read.marker", "1");
}
JS
```

Run it:

```sh
set +e
whoathere vm detonate --workspace "$HOME/whoathere-fresh-smoke/npm-canary" \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  npm -- install > /tmp/whoathere-fresh-user-npm-canary.json
status=$?
set -e
test "$status" -eq 20
grep -q 'deny_malicious_behavior' /tmp/whoathere-fresh-user-npm-canary.json
test ! -e "$HOME/whoathere-fresh-smoke/npm-canary/canary-read.marker"
test ! -d "$HOME/whoathere-fresh-smoke/npm-canary/node_modules"
```

## Phase 5: Clean Copy-Back

Run this phase only if scanner readiness passed in Phase 2.

```sh
cd "$HOME/whoathere-fresh-smoke/npm-clean"
whoathere scanners run --workspace "$PWD" \
  --ecosystem npm \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json > /tmp/whoathere-fresh-user-scanner-clean.json

whoathere package-risk assess --workspace "$PWD" \
  --ecosystem npm \
  --state-dir "$WHOATHERE_STATE" \
  --scanner-receipt /tmp/whoathere-fresh-user-scanner-clean.json \
  --json > /tmp/whoathere-fresh-user-risk-clean.json

grep -q '"overall_verdict": "auto_sync_candidate"' /tmp/whoathere-fresh-user-risk-clean.json

PACKAGE_RISK_RECEIPT=$(
  find "$WHOATHERE_STATE/package-risk/receipts" -name '*.json' -type f | sort | tail -n 1
)
```

For the current release candidate, a fresh user state is expected to fail closed here unless release
engineering has generated a current release-notarization receipt for this same state. Run the
copy-back command and verify the fail-closed behavior first:

```sh
set +e
whoathere vm detonate --workspace "$PWD" \
  --state-dir "$WHOATHERE_STATE" \
  --package-risk-receipt "$PACKAGE_RISK_RECEIPT" \
  --execute --sync-back --json \
  npm -- install > /tmp/whoathere-fresh-user-sync-clean.json
status=$?
set -e
```

Expected acceptance checks for the current fresh-user test:

```sh
test "$status" -eq 20
grep -q '"applied": false' /tmp/whoathere-fresh-user-sync-clean.json
grep -q 'release_notarization' /tmp/whoathere-fresh-user-sync-clean.json
test ! -e "$HOME/whoathere-fresh-smoke/npm-clean/clean.marker"
```

This is not a product failure for the fresh-user test. It proves the current release candidate does
not copy VM outputs into a new user account unless the release trust evidence is present.

When release-evidence handoff is implemented, rerun the same command and use these acceptance
checks instead:

```sh
test "$status" -eq 0
grep -q '"applied": true' /tmp/whoathere-fresh-user-sync-clean.json
grep -q '"verdict": "allow_observed_clean"' /tmp/whoathere-fresh-user-sync-clean.json
test -e "$HOME/whoathere-fresh-smoke/npm-clean/clean.marker"
```

## Phase 6: Doctor Release Readiness

After the copy-back fail-closed check:

```sh
whoathere vm suspend --state-dir "$WHOATHERE_STATE" --execute
whoathere doctor --state-dir "$WHOATHERE_STATE" --json > /tmp/whoathere-fresh-user-doctor-final.json
```

Expected acceptance checks for the current fresh-user test:

```sh
grep -q '"release_ready": false' /tmp/whoathere-fresh-user-doctor-final.json
grep -q 'release_signature_notarization_not_complete' /tmp/whoathere-fresh-user-doctor-final.json
```

If release-evidence handoff has been implemented for the fresh user state, expected checks become:

```sh
grep -q '"release_ready": true' /tmp/whoathere-fresh-user-doctor-final.json
grep -q '"release_blocking_reason_codes": \[\]' /tmp/whoathere-fresh-user-doctor-final.json
grep -q '"verified": true' /tmp/whoathere-fresh-user-doctor-final.json
```

If scanners were skipped, expected result remains `release_ready=false` with sync-back-related
blockers. That is acceptable for a partial fresh-user install and VM detonation test, but not for
full fresh-user release readiness.

## Phase 7: Security Review Checks

Manually review the temporary JSON outputs:

- No raw fake canary values are present.
- No host secret paths are present.
- The fresh user's outputs do not reference `/Users/jdc/src/whoathere` except for the staged archive
  path if you deliberately used it.
- Denied cases exit `20`.
- Copy-back is absent unless `--sync-back` is explicitly passed.
- `sync_back.applied` is false for malicious or unsupported cases.
- `host_package_execution_enabled` is false.
- `high_risk_package_execution_enabled` is false.

## Cleanup

From the fresh user account:

```sh
whoathere vm suspend --state-dir "$WHOATHERE_STATE" --execute || true
whoathere vm prune --state-dir "$WHOATHERE_STATE" --execute || true
```

Remove test projects if desired:

```sh
rm -rf "$HOME/whoathere-fresh-smoke"
```

Remove the fresh user's WhoaThere state only after preserving any receipts you want:

```sh
rm -rf "$HOME/.whoathere"
```

From the main account, remove the staged archive only when no other user needs it:

```sh
rm -rf /Users/Shared/whoathere-beta
```

Delete the `whoatherebeta` macOS user account through System Settings > Users & Groups after the
test is complete.
