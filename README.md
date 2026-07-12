# WhoaThere

WhoaThere is a command-line tool that helps Python and Node developers install packages with less
risk.

Modern package managers do more than download files. An `npm install`, `pip install`, or `uv sync`
can run package code during install, build, import, or first use. That is useful for legitimate
packages, but it is also how compromised packages steal tokens, read SSH keys, fetch second-stage
payloads, or behave differently on CI and developer laptops.

WhoaThere's current macOS beta takes a conservative approach: run supported package workflows away
from your host machine, watch what happens, and copy results back only when the evidence is clean
enough.

## Current Status

The active target is an Apple Silicon macOS local beta. The most recent major product experiment
was the July 1, 2026 actual-malware evaluation on a disposable Scaleway Mac.

What that means:

- CLI-only. No GUI and no installer package are required.
- Built for local Python and Node development.
- Uses a separate macOS VM as the main safety boundary.
- Supports scanner and package-risk checks as extra evidence.
- Blocks or asks for manual review on package shapes that are too risky for this beta.
- Does not depend on AWS, a company package registry, or a cloud service.

Current claim boundary:

- Credible now: WhoaThere can be positioned as a containment and package-workflow admission tool
  for supported local macOS workflows.
- Not credible yet: broad supply-chain malware detection, low false-positive claims, arbitrary
  npm/PyPI package safety, live C2 detection, or enterprise CI/package-proxy enforcement.

This is useful security tooling, not a promise that arbitrary packages are safe.

The artifact-native detection build is now exercising a separately measured Linux VM backend. Its
first ten physical inert guest-plus-host conformance cases passed on one measured identity with
authenticated process, file, and packet/lifecycle evidence, but the backend is still unqualified
until all 38 closed cases pass.
See the [execution plan](docs/product-build-run/artifact-native-detection-execution-plan.md) and
[IPv6-connect checkpoint](docs/product-build-run/artifact-native-linux-vz-ipv6-connect-checkpoint-2026-07-12.md).

## Actual Malware Experiment

On July 1, 2026, WhoaThere was evaluated against 11 real npm/PyPI supply-chain malware artifacts
from a restricted MalwareBazaar-backed corpus on a disposable Scaleway Mac. The malware was run only
through the VM-backed path, with no host package execution, no sync-back, no live C2, and no live
second-stage fetching.

Result:

- Safety gate passed: 0 unsafe allows, 0 host executions, 0 sync-backs, and 0 restricted-material
  leaks in sanitized evidence.
- Detection gate failed: 7 of 11 malicious artifacts produced behavior-specific evidence, or
  63.6%, below the 85-90% target.
- Benign gate was not measured in the final campaign.
- Network evidence is egress-denied/no-live-C2, not sinkhole/replay telemetry.

The correct read is: **containment worked; behavior detection is not release-credible yet**.

Start with:

- `docs/product-build-run/whoathere-actual-malware-experimental-run-2026-07-01.html`
- `docs/product-build-run/actual-malware-evaluation.md`
- `docs/product-build-run/actual-malware-execution-plan-5-8.md`

Restricted raw samples and sanitized local evidence snapshots live outside git under `.whoathere/`.
Do not move them into source-controlled paths.

## Release Direction

The strongest near-term release option is a **public local containment preview**:

> WhoaThere safely detonates supported Python and Node package setup workflows in a local macOS VM
> before anything runs on your host or syncs back to your project. It composes with existing
> scanners, but does not trust scanner output alone.

Avoid claims such as:

- "detects supply-chain malware"
- "makes npm/pip install safe"
- "replaces OSV-Scanner, pip-audit, npm audit, Trivy, GuardDog, Packj, or provenance"
- "supports arbitrary public packages, native extensions, wheels, direct URLs, VCS, editable
  installs, or runtime app protection"

Next gates before a detection-credible beta:

- Add first-class PyPI wheel metadata handling and wheel detonation routing.
- Normalize nested PyPI sdist roots before package-risk and VM planning.
- Add package-artifact detonation for npm lifecycle hooks, including CI-gated behavior.
- Rerun the four `safe_block` malware cases and reach at least 85% behavior-specific evidence.
- Run benign controls and report hard-deny/manual-review rates.
- Preserve the safety invariants: no host execution, no sync-back, no live C2, and no redaction
  leaks.

## Why This Exists

Package supply-chain attacks often work because a developer or CI runner asks a trusted tool to
install something that has become untrusted:

- a maintainer account is compromised
- a package name is typo-squatted
- an internal package name is confused with a public package
- a new version adds a malicious install script
- a Python build backend or `.pth` file runs code unexpectedly
- a binary wheel or native extension hides behavior scanners cannot easily inspect
- a package keeps the same public API but adds credential theft in normal-looking code

Traditional scanners help, but they are not enough by themselves. WhoaThere combines several
signals and keeps risky execution away from your host.

## How It Works

At a high level:

1. You point WhoaThere at a project or run a protected package workflow.
2. WhoaThere mirrors only the needed project files into a separate macOS VM.
3. Package-manager work runs inside that VM, not directly on your host.
4. The VM contains fake credentials and canaries instead of your real secrets.
5. WhoaThere records package behavior, scanner results, package type, version age, diffs, and local
   package history.
6. It decides whether the result is safe enough to copy back.
7. Copy-back is deny-by-default and limited to narrow project outputs.

For example, pure package outputs with clean evidence may be eligible for copy-back. Native
extensions, binary wheels, direct URLs, VCS dependencies, editable installs, suspicious diffs, new
install scripts, startup hooks, or network/credential behavior stay blocked or require manual
review.

## What It Helps With

WhoaThere can improve local development safety for:

- npm lifecycle scripts such as `postinstall`, `prepare`, and package `bin` behavior
- agent-assisted "clone this repo and run setup" workflows that hide DNS TXT second-stage payloads,
  fetched shell stagers, or reverse-shell capability in install scripts
- Python build hooks, import-time behavior, and `.pth` startup hooks
- delayed behavior such as `CI=true` activation
- macOS-specific payloads
- packages that touch fake credentials during common API use
- DNS/HTTPS exfiltration attempts visible from the VM
- surprise upgrades when a last-known-good local package version exists
- unpinned dependency specs that would otherwise float to a new version
- known vulnerable packages when external scanners are available

## What It Does Not Do

WhoaThere does not:

- prove arbitrary packages are safe
- protect your app after you choose to run package code normally
- make native extensions or binary wheels safe to auto-copy back
- safely auto-approve direct URL, VCS, editable, unknown, or suspicious packages
- replace code review for subtle malicious behavior hidden behind normal APIs
- provide enterprise package registry enforcement in the current local beta
- use scanner findings as the only reason to allow package output onto the host

If WhoaThere cannot get enough evidence, the beta should fail closed rather than guess.

## Install From Private GitHub

For now, this project should stay private. A clean Apple Silicon Mac needs an authenticated GitHub
CLI session before it can download the release archive.

```sh
gh auth login -h github.com
gh repo clone joncooper/whoathere
cd whoathere
scripts/whoathere-install-from-github.sh --private --repo joncooper/whoathere --prefix "$HOME/.whoathere"
export PATH="$HOME/.whoathere/bin:$PATH"
whoathere doctor --json
```

To install a specific beta release:

```sh
scripts/whoathere-install-from-github.sh --private \
  --repo joncooper/whoathere \
  --tag macos-local-beta-a212742 \
  --prefix "$HOME/.whoathere"
```

The installer downloads the private GitHub Release archive through `gh release download`, verifies
the SHA-256 checksum, extracts it, and runs the packaged user-level installer. It does not use
`sudo`.

Distribution details are in
`docs/product-build-run/github-distribution.md`.

## First Commands

Set a state directory for the local beta:

```sh
export WHOATHERE_STATE="$HOME/.whoathere/macos-vm-validation"
```

Check readiness:

```sh
whoathere doctor --state-dir "$WHOATHERE_STATE" --json
```

Initialize the VM from a local restore image:

```sh
whoathere vm init --state-dir "$WHOATHERE_STATE" \
  --restore-image /absolute/path/to/macos-restore.ipsw \
  --execute
```

Or let the helper fetch Apple's current restore image:

```sh
whoathere vm init --state-dir "$WHOATHERE_STATE" \
  --fetch-latest-restore-image \
  --execute
```

Start the VM:

```sh
whoathere vm start --state-dir "$WHOATHERE_STATE" --execute
```

Run scanners for a project:

```sh
whoathere scanners run --workspace /absolute/path/to/project \
  --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" \
  --execute \
  --json > scanner-receipt.json
```

Assess package risk:

```sh
whoathere package-risk assess --workspace /absolute/path/to/project \
  --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" \
  --scanner-receipt scanner-receipt.json \
  --json > package-risk.json
```

For an untrusted agent-generated or newly cloned repo, use the intake wrapper before running setup
commands on the host:

```sh
whoathere intake assess --workspace /absolute/path/to/project \
  --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" \
  --scanner-receipt scanner-receipt.json \
  --execute \
  --json \
  npm -- install
```

`intake assess` runs package-risk assessment with local AI review requested by default, detonates the
requested install workflow in the VM with fake canaries, disables sync-back, and only returns clean
when both package-risk and dynamic VM evidence are clean. Use `--no-ai-review` for deterministic
local-only testing when a local model is unavailable.

Preview mode is intentionally fail-closed:

```sh
whoathere intake assess --workspace /absolute/path/to/project \
  --ecosystem auto \
  --state-dir "$WHOATHERE_STATE" \
  --json \
  npm -- install
```

That assessment treats lifecycle scripts, credential/environment reads, DNS TXT payload stagers,
fetched shell execution, reverse-shell capability, process spawning, native/binary payloads,
direct/VCS sources, delayed CI activation, missing scanner evidence, and missing VM execution as
manual-review or deny signals. It does not execute package code on the host.

Run a local project workflow in the VM without copy-back:

```sh
whoathere vm detonate --workspace /absolute/path/to/project \
  --state-dir "$WHOATHERE_STATE" \
  --execute --json \
  npm -- install
```

The detailed CLI guide is in
`docs/product-build-run/macos-local-beta-cli-guide.md`.

## Testing A Clean Mac

For a fresh Mac or clean user account, follow:

```text
docs/product-build-run/macos-local-beta-fresh-user-test-plan.md
```

That plan covers install, `doctor`, VM setup, scanner readiness, mock malicious fixtures, and real
project trials.

## Repository Layout

```text
whoathere/     Rust workspace for the CLI, policy logic, scanners, VM workflow, and tests
scripts/       Packaging, scanner, release, and smoke-test scripts
docs/          Architecture notes, build plans, checkpoints, and user-facing runbooks
dist/          Local release artifacts, ignored by git
.whoathere/    Local runtime state and scanner cache, ignored by git
```

The main code lives in `whoathere/`.

## Development Checks

From the repo root:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vm red-team-gate
```

Useful smoke checks:

```sh
scripts/whoathere-scanner-integration-smoke.sh
scripts/whoathere-package-risk-smoke.sh
scripts/whoathere-real-world-attack-harness.sh
scripts/whoathere-local-beta-pressure-suite.sh
```

Some checks require Apple Silicon macOS, Xcode tooling, a provisioned WhoaThere VM, or local scanner
tools.

## Security Posture

WhoaThere is intentionally conservative.

The current local beta is designed to make common Python and Node package workflows safer for a
developer machine. It is not a complete answer to package supply-chain risk. The product should earn
trust by showing its work: clear verdicts, reason codes, redacted evidence, no silent public
fallback, no broad break-glass path, and no claims that scanners or AI review can prove a package
safe by themselves.

The broader vision includes an enterprise package proxy and cache, but the current release target is
the local macOS CLI.
