# WhoaThere macOS Local Beta CLI Guide

This guide is for Python and Node developers using the current Apple Silicon macOS local beta from
the command line. It avoids installer, GUI, packaging, AWS, and enterprise Vault work.

## What This Beta Does

WhoaThere gives you a safer way to test package installs before they touch your normal project
files. It mirrors a small project into a macOS VM, runs supported npm, pip, or uv workflows there,
plants fake credentials in the VM, watches for risky behavior, and copies files back only when
explicitly requested and backed by clean evidence.

It is useful because malicious packages often attack during install, build, import, or first API
use. WhoaThere moves those moments away from your host and records why it allowed, denied, or asked
for review.

## What It Does Not Do

- It does not prove arbitrary packages are safe.
- It does not protect your app after you import and run a package in normal application code.
- It does not auto-trust native extensions, binary wheels, direct URLs, Git/VCS dependencies,
  editable installs, unknown artifacts, or suspicious package classes.
- It does not use public registry fallback for this beta.
- It does not let scanner results authorize file copy-back by themselves.

## Build The CLI And Helper

From the repo root:

```sh
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli --bin whoathere
```

Build the macOS VM helper:

```sh
cd /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper
swift test
swift build
./scripts/sign-local-helper.sh
```

Set these shell variables:

```sh
export WHOATHERE=/Users/jdc/src/whoathere/whoathere/target/debug/whoathere
export WHOATHERE_STATE=/Users/jdc/.whoathere/macos-vm-validation
export WHOATHERE_HELPER=/Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
```

Run `./scripts/sign-local-helper.sh` again after every `swift build`.

## Check Readiness

Use `doctor` first:

```sh
$WHOATHERE doctor --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --json
```

Useful fields:

- `release_ready`: whether the current local beta checks are satisfied.
- `reason_codes`: what is missing or stale.
- `guest_reprovision_required`: whether the VM guest tools need to be refreshed.
- `guest_reprovision_command`: the admin command to run when guest tools are stale.
- `package_acquisition_policy`: should remain `local_only_no_public_resolver` for this beta.

## Initialize Or Refresh The VM

Create the VM with a local restore image:

```sh
$WHOATHERE vm init --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --restore-image /absolute/path/to/macos-restore.ipsw --execute
```

Or fetch Apple's current restore image:

```sh
$WHOATHERE vm init --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --fetch-latest-restore-image --execute
```

Before refreshing guest tools:

```sh
$WHOATHERE vm reprovision --preflight --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER"
```

Then run the printed admin command in an interactive terminal. After that:

```sh
$WHOATHERE vm status --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" --json
```

## Optional Scanner Evidence

Bootstrap scanners:

```sh
scripts/whoathere-bootstrap-scanners.sh
```

Run scanners against a project:

```sh
$WHOATHERE scanners run --workspace /absolute/path/to/project --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" --execute --json
```

Scanner output is evidence, not permission. A scanner finding should make you more cautious. A clean
scanner run does not make a package safe by itself.

## Assess Package Risk

Run package-risk assessment before VM sync-back:

```sh
$WHOATHERE package-risk assess --workspace /absolute/path/to/project --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" --json
```

With scanner evidence:

```sh
$WHOATHERE package-risk assess --workspace /absolute/path/to/project --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" --scanner-receipt /path/to/scanner-receipt.json --json
```

Read these fields first:

- `overall_verdict`: `allow`, `manual_review`, or `deny`.
- `packages`: each package and the reason codes behind its verdict.
- `host_effect`: what did or did not happen on your host.
- `recommended_actions`: what to do next.
- `receipt_path`: the receipt to use later if the result is clean enough for sync-back.

Fresh local state usually produces `manual_review` because there is no approved history yet.

## Detonate Without Copy-Back

Python local project:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --execute --json pip -- install .
```

Python requirements that only point at the local project:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --execute --json pip -- install -r requirements.txt
```

uv local project:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --execute --json uv -- pip install .
```

npm local project with no external dependency resolution:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/npm-project \
  --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --execute --json npm -- install
```

When a safe Python import module is inferred, VM detonation also runs a narrow API-use probe inside
the VM. It imports the module and tries common zero-argument functions and client methods. This
catches some packages that look normal until first use, but it is not complete runtime protection.

## Copy Files Back

Copy-back is off unless you request it. Use it only with a clean package-risk receipt for the same
workspace:

```sh
$WHOATHERE vm detonate --workspace /absolute/path/to/python-project \
  --state-dir "$WHOATHERE_STATE" --helper "$WHOATHERE_HELPER" \
  --package-risk-receipt /path/to/package-risk-receipt.json \
  --execute --sync-back --json pip -- install .
```

Copy-back still fails closed if the guest saw canary access, network markers, unexpected output,
symlink escapes, traversal, wrong workspace, wrong receipt, stale evidence, or unsupported package
classes.

## Exit Codes

- `0`: allowed or clean.
- `20`: denied or failed closed.
- `22`: manual review required.
- `64`: command misuse or invalid arguments.
- `70`: internal error.

In automation, treat anything other than `0` as not safe to continue.

## Common Blocked Cases

- Public package resolution from npm, PyPI, or uv is blocked for this beta.
- Unpinned dependencies with no last-known-good local approval require review.
- Fresh public versions are held by the age gate.
- New install scripts, `.pth` startup hooks, native markers, binary wheels, direct URLs, VCS sources,
  editable installs, npm command shims, Python console scripts, and local path escapes prevent
  automatic copy-back.
- Missing or stale VM guest tooling fails before detonation.
- Missing scanners are reported but do not block the current local-only beta by themselves.

## Recovery

If `doctor` says the guest is stale, run the reprovision command it prints.

If scanner or package-risk output says `manual_review`, read the package-level reason codes. Approve
only after reviewing the package and receipt:

```sh
$WHOATHERE package-risk approve --receipt /path/to/package-risk-receipt.json \
  --reason "reviewed local beta baseline" --state-dir "$WHOATHERE_STATE" --json
```

If a VM run is blocked because the package class is native, binary, direct URL, VCS, editable, or
unknown, leave it blocked for this beta unless you are intentionally doing manual research in a
separate environment.

## Validation Commands

Before relying on a local checkout, run:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
swift test --package-path whoathere/helpers/macos-vm-helper
whoathere/helpers/macos-vm-helper/scripts/validate-guest-agent-project-payload.sh
scripts/whoathere-package-risk-smoke.sh
scripts/whoathere-real-world-attack-harness.sh
scripts/whoathere-local-beta-pressure-smoke.sh
```

Run the live VM validation when a provisioned VM is available:

```sh
whoathere/helpers/macos-vm-helper/scripts/validate-project-detonation.sh
```
