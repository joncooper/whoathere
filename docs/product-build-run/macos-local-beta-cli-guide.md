# WhoaThere macOS Local Beta CLI Guide

This guide is for Python and Node developers using the Apple Silicon macOS local beta from the
command line. It assumes a signed and notarized preview archive such as:

```text
dist/whoathere-macos-arm64-preview-a212742.tar.gz
```

WhoaThere is not a general package-safety oracle. It is a way to run supported package workflows in
a separate macOS VM, watch for dangerous behavior, and copy back only narrow outputs when the
evidence is clean.

## What It Helps With

WhoaThere improves local development safety when a package does something risky during install,
build, import, or first simple API use. It can help catch or block:

- npm lifecycle scripts that read fake credentials or try network exfiltration.
- Python `setup.py`, PEP 517 build backends, import-time payloads, and `.pth` startup hooks.
- npm or Python packages that look API-compatible but touch fake secrets during common use.
- delayed `CI=true`, macOS-only, DNS/HTTPS exfiltration, binary/native marker, direct URL, VCS, and
  editable dependency cases.
- surprise upgrades when local last-known-good package memory exists.

## What It Does Not Do

- It does not prove arbitrary packages are safe.
- It does not protect your application after you run admitted package code normally.
- It does not safely auto-sync native extensions, binary wheels, direct URLs, VCS dependencies,
  editable installs, global/system Python installs, unknown artifacts, or suspicious outputs.
- It does not use public registry fallback in this beta.
- It does not let scanner results authorize file copy-back by themselves.
- It does not replace code review for packages that hide malicious behavior behind ordinary runtime
  APIs that WhoaThere did not probe.

## Install From The Preview Archive

Extract and install for the current user only:

```sh
cd /path/to/release-artifacts
shasum -a 256 -c whoathere-macos-arm64-preview-a212742.tar.gz.sha256
tar -xzf whoathere-macos-arm64-preview-a212742.tar.gz
cd whoathere-macos-arm64-preview-a212742
./install-macos-preview.sh --dry-run --prefix "$HOME/.whoathere"
./install-macos-preview.sh --prefix "$HOME/.whoathere"
```

Add the wrapper to your shell path:

```sh
export PATH="$HOME/.whoathere/bin:/usr/bin:/bin:/usr/sbin:/sbin"
```

The wrapper points `whoathere` at the packaged VM helper. You should not need to pass `--helper`
when using the installed wrapper.

Confirm the CLI runs:

```sh
whoathere --help
```

Use one state directory for the beta VM and receipts:

```sh
export WHOATHERE_STATE="$HOME/.whoathere/macos-vm-validation"
```

## Check Readiness

Run:

```sh
whoathere doctor --state-dir "$WHOATHERE_STATE" --json
```

Read these fields first:

- `release_ready`: `true` means this local state has current release evidence.
- `release_blocking_reason_codes`: what is missing or stale when `release_ready` is false.
- `guest_reprovision_required`: whether the VM guest tools must be refreshed.
- `guest_reprovision_command`: the admin command to run when guest tooling is stale.
- `package_acquisition_policy`: should be `local_only_no_public_resolver`.
- `manual_review_classes`: package classes that stay conservative in this beta.

It is normal for a fresh install to report `release_ready=false` until the VM is initialized,
provisioned, and validated for that user state.

## Initialize The VM

Create a VM from a local restore image:

```sh
whoathere vm init --state-dir "$WHOATHERE_STATE" \
  --restore-image /absolute/path/to/macos-restore.ipsw \
  --execute
```

Or allow the helper to fetch Apple's current restore image:

```sh
whoathere vm init --state-dir "$WHOATHERE_STATE" \
  --fetch-latest-restore-image \
  --execute
```

Refresh guest tools when `doctor` asks for it:

```sh
whoathere vm reprovision --preflight --state-dir "$WHOATHERE_STATE"
```

Run the printed `sudo ... provision-guest-readiness.sh ...` command in an interactive admin-capable
Terminal. Then check:

```sh
whoathere vm status --state-dir "$WHOATHERE_STATE" --json
```

Start and health-check the VM:

```sh
whoathere vm start --state-dir "$WHOATHERE_STATE" --execute
whoathere vm health --state-dir "$WHOATHERE_STATE"
```

Stop it when finished:

```sh
whoathere vm suspend --state-dir "$WHOATHERE_STATE" --execute
```

## Optional Scanner Setup

Scanners add useful evidence. They do not replace the VM and cannot authorize copy-back by
themselves.

If Homebrew and uv are available, install the current core tools:

```sh
brew install osv-scanner syft grype trivy scorecard
uv tool install guarddog
uv tool install pip-audit
```

Check scanner readiness:

```sh
whoathere scanners list --json
```

Run scanners for a project:

```sh
whoathere scanners run --workspace /absolute/path/to/project \
  --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" \
  --execute \
  --json > scanner-receipt.json
```

Scanner output is normalized and redacted. It should not include raw package dumps, tokens,
canaries, or host secret paths.

## Assess Package Risk

Assess a workspace before copy-back:

```sh
whoathere package-risk assess --workspace /absolute/path/to/project \
  --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" \
  --scanner-receipt scanner-receipt.json \
  --json > package-risk.json
```

Read:

- `overall_verdict`: `auto_sync_candidate`, `manual_review`, or `deny`.
- `decision_summary`: plain-language summary.
- `host_effect`: what happened on the host. Package-risk assessment does not run package code.
- `recommended_actions`: next practical steps.
- `packages`: per-package verdicts and reason codes.

The printed `receipt_path` is intentionally redacted. To find the newest receipt:

```sh
PACKAGE_RISK_RECEIPT=$(
  find "$WHOATHERE_STATE/package-risk/receipts" -name '*.json' -type f | sort | tail -n 1
)
printf '%s\n' "$PACKAGE_RISK_RECEIPT"
```

Fresh local state often produces `manual_review` because no last-known-good version has been
approved yet.

Approve a local baseline only after review:

```sh
whoathere package-risk approve --receipt "$PACKAGE_RISK_RECEIPT" \
  --reason "reviewed local beta baseline" \
  --state-dir "$WHOATHERE_STATE" \
  --json
```

## Run Without Copy-Back

Python local project:

```sh
whoathere vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  pip -- install .
```

Python requirements that only point at local project files:

```sh
whoathere vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  pip -- install -r requirements.txt
```

uv local project:

```sh
whoathere vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  uv -- pip install .
```

npm local project with no external dependency resolution:

```sh
whoathere vm detonate --workspace /absolute/path/to/npm-project \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  npm -- install
```

Useful output fields:

- `verdict`: top-level decision.
- `guest_job.verdict`: what the guest observed.
- `guest_job.canary_access_detected`: whether fake credentials were touched.
- `guest_job.network_attempt_detected`: whether network behavior was observed.
- `sync_back.applied`: whether anything copied back to the host.
- `reason_codes`: why the command allowed, denied, or asked for review.

## Copy Files Back

Copy-back is always opt-in. Use it only after package-risk says the same workspace is an
`auto_sync_candidate` and you have the latest receipt path:

```sh
whoathere vm detonate --workspace /absolute/path/to/project \
  --state-dir "$WHOATHERE_STATE" \
  --package-risk-receipt "$PACKAGE_RISK_RECEIPT" \
  --execute --sync-back --json \
  npm -- install
```

For Python:

```sh
whoathere vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" \
  --package-risk-receipt "$PACKAGE_RISK_RECEIPT" \
  --execute --sync-back --json \
  pip -- install .
```

Copy-back still fails closed if the guest saw canary access, network markers, unexpected outputs,
symlink escapes, path traversal, a wrong workspace, a wrong receipt, stale evidence, or unsupported
package classes.

Current release-candidate caveat: copy-back also requires a current release-notarization receipt in
the WhoaThere state directory. On the build validation state this is already present and `doctor`
reports `release_ready=true`. A brand-new user state will not have that receipt until release
evidence handoff is productized or release engineering generates the receipt for that state. Without
it, `--sync-back` should fail closed before copying files back.

## Exit Codes

- `0`: allowed or clean.
- `20`: denied or failed closed.
- `22`: manual review required.
- `64`: command misuse or invalid arguments.
- `70`: internal error.

In scripts, treat anything other than `0` as "do not continue as if the package is safe."

## Common Blocked Cases

- Public npm, PyPI, or uv dependency resolution is blocked for this beta.
- Unpinned dependencies without last-known-good local approval require review.
- Fresh public versions are held by the 7 day age gate.
- New lifecycle scripts, `.pth` startup hooks, native markers, binary wheels, direct URLs, VCS
  sources, editable installs, npm command shims, Python console scripts, and local path escapes
  prevent automatic copy-back.
- Missing or stale VM guest tooling fails before detonation.
- Missing scanners are visible in readiness output. They do not block local-only detonation, but
  clean scanner evidence is required for public-package auto-sync decisions.

## Minimal Smoke Project

Create a clean npm project:

```sh
mkdir -p "$HOME/whoathere-smoke/npm-clean"
cd "$HOME/whoathere-smoke/npm-clean"
cat > package.json <<'JSON'
{
  "name": "whoathere-smoke-npm-clean",
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

Run it in the VM without copy-back:

```sh
whoathere vm detonate --workspace "$HOME/whoathere-smoke/npm-clean" \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  npm -- install
```

The command should exit `0`, report an observed-clean verdict, and not create `clean.marker` in the
host project unless you later run a clean `--sync-back` flow.

Create a mock malicious npm project:

```sh
mkdir -p "$HOME/whoathere-smoke/npm-canary"
cd "$HOME/whoathere-smoke/npm-canary"
cat > package.json <<'JSON'
{
  "name": "whoathere-smoke-npm-canary",
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
whoathere vm detonate --workspace "$HOME/whoathere-smoke/npm-canary" \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  npm -- install
```

Expected result: exit `20`, no host `canary-read.marker`, and reason codes showing malicious VM
behavior.

## Daily Workflow

1. Run `whoathere doctor --state-dir "$WHOATHERE_STATE" --json`.
2. Keep public dependency resolution out of the workflow unless you are intentionally testing a
   blocked/manual-review case.
3. Run scanners when you want copy-back eligibility.
4. Run `package-risk assess`.
5. Run `vm detonate` without `--sync-back` first.
6. Use `--sync-back` only for supported pure/safe classes with clean package-risk, VM evidence, and
   current release evidence in the same state directory.
7. Run `vm suspend --execute` when finished.
