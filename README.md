# WhoaThere

WhoaThere is a command-line tool that helps Python and Node developers install packages with less
risk.

Modern package managers do more than download files. An `npm install`, `pip install`, or `uv sync`
can run package code during install, build, import, or first use. That is useful for legitimate
packages, but it is also how compromised packages steal tokens, read SSH keys, fetch second-stage
payloads, or behave differently on CI and developer laptops.

WhoaThere's current macOS beta takes a conservative approach: run supported package workflows away
from your host machine, watch what happens, and copy results back only when the evidence is clean
enough. The established project-workflow preview uses a separate macOS guest; the newer
exact-artifact path uses fresh disposable Linux VZ guests with no sync-back.

## Current Status

The active target is an Apple Silicon macOS local beta. The July 1, 2026 actual-malware evaluation
on a disposable Scaleway Mac remains the finalized restricted-malware experimental baseline. Since
then, substantial inert and public-neighbor experiments have exercised the exact-artifact path.

What that means:

- CLI-only. No GUI and no installer package are required.
- Built for local Python and Node development.
- Uses a separate macOS VM for the established workflow preview and disposable Linux VZ guests for
  exact npm and PyPI artifacts.
- Supports scanner and package-risk checks as extra evidence.
- Blocks or asks for manual review on package shapes that are too risky for this beta.
- Keeps core containment local-first; hosted AI review and restricted cloud-lab validation are
  explicit optional modes rather than hidden dependencies.

Current claim boundary:

- Credible now: WhoaThere can be positioned as a containment and package-workflow admission tool
  for supported local macOS workflows.
- Not credible yet: broad supply-chain malware detection, low false-positive claims, arbitrary
  npm/PyPI package safety, live C2 detection, or enterprise CI/package-proxy enforcement.

This is useful security tooling, not a promise that arbitrary packages are safe.

## Try Exact Artifact Inspection

WhoaThere now has a human-readable exact-artifact command for npm tarballs, Python wheels, and
Python sdists:

```sh
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli
whoathere/target/debug/whoathere inspect ./package.tgz
```

The result leads with one conservative action:

- `BLOCK - malicious capability found in package` when eligible static evidence is present;
- `BLOCK - malicious behavior observed in disposable VM` only when typed behavior is bound to the
  qualified Linux VZ execution path; or
- `REVIEW - WhoaThere cannot establish that this artifact is safe` when evidence is incomplete or
  has no behavior-specific positive.

Reports identify the exact artifact, evidence modality, behavior, confidence, safe citations, and
coverage gaps without printing package source or private host paths. They never install the
artifact or grant sync-back authority. Automation can request the existing machine contract with
`whoathere inspect ./package.tgz --json`; the legacy `whoathere artifact inspect` JSON command
remains compatible.

### Reopen a saved report without the package

Save the machine-readable inspection once, record its SHA-256 through trusted custody, and render
it later without retaining or reopening the artifact:

```sh
whoathere/target/debug/whoathere inspect ./package.tgz --json > inspection.json
shasum -a 256 inspection.json
whoathere/target/debug/whoathere report render inspection.json \
  --report-sha256 sha256:<the-digest-printed-above>
```

The saved-report command verifies the exact file bytes and the complete typed V1 report structure
before reusing the human `BLOCK` or `REVIEW` renderer. It rejects malformed, unknown-version,
digest-mismatched, cross-bound, or authority-bearing reports and never follows paths embedded in
the report. Digest matching is integrity, not producer authentication: obtain the expected digest
through a channel you trust. Rendering does not rerun analysis, open package bytes, install a
package, grant admission, or enable sync-back.

The artifact-native detection build now has physically exercised exact-artifact Linux VZ routes for
npm tarballs, pure-Python wheels, and nested-root PEP 517 sdists. Exact npm installation completed
under both CI profiles, one wheel completed its eight install and trigger actions, and the sdist
path completed build, derived-wheel inspection and install, and import. A fresh canary-bearing sdist
import run also crossed the previously failing large-evidence boundary, retained 5.95 MB of signed
runtime evidence, and projected the package trigger, protected PyPI-token reads, and local-sinkhole
sends. Observe-only Codex specialists cited those exact events as lifecycle, canary-access, and
network findings while explicitly declining to infer token exfiltration or grant admission.

In follow-up restricted-lab diagnostics, both previously missed Telnyx wheels completed
exact-artifact runs in fresh disposable Linux VZ guests with the safety invariants intact. Their
sanitized, signed behavior bundles were reviewed by subscription-backed Codex: the split
diagnostics preserved the deterministic behavior detections, and Codex confirmed each package's
import trigger from the typed telemetry. This is an encouraging end-to-end validation of the new
wheel path, but the split workflow is diagnostic rather than claim-bearing and does not change the
7/11 known-malware baseline.

The npm lane also advanced on July 17. What first looked like a requalification reboot was only SSH
source-IP loss after Cloudflare WARP changed the operator's egress; the approved cloud Mac had not
failed. The public benign `sbx` `2.1.0` artifact then completed both CI profiles safely. Under a
separate restricted-lab approval, `mb-npm-sbx-45.0.2` was unpacked only on that cloud Mac for a
deterministic static scan. No VM started, no helper or clone remained, no package code executed on
the host, no sync-back occurred, and no live C2 was contacted. The static scan classified the
artifact as malicious with five eligible detections, including sensitive-path access and
exfiltration/process capability.

Digest-bound offline npm closure support is now implemented and physically qualified. On July 18,
a wholly inert dependency-bearing package shaped like the missed `sbx` sample completed in fresh
disposable guests under both `CI=false` and `CI=true`. Four sealed closure tarballs were installed
first with lifecycle scripts disabled; only the exact target tarball ran its lifecycle scripts.
Both profiles produced 29-event behavior bundles, stopped their VMs, destroyed their clones,
exposed no public route, and performed no sync-back.

That final qualification also found and fixed two concrete integration defects: the host helper
still expected an older runtime filename, and an emergency kernel message could replace one
base64 evidence fragment on the shared serial console. The rebuilt helper now uses the production
runtime name, while the parser can recover only one uniquely authenticated fragment matching both
the declared length and SHA-256. The full 243-test Swift suite passed before the exact two-profile
run was repeated successfully. Subscription-backed Codex then reviewed both signed bundles, cited
the exact npm lifecycle events, and correctly left missing sensor coverage inconclusive rather
than calling the package clean.

That qualified path has now reached the real missed npm artifact. Under a fresh one-sample
restricted-lab clearance, the exact `mb-npm-sbx-45.0.2` tarball ran only inside disposable Linux
VZ guests with its four exact public dependency tarballs, restrictive host networking, no
sync-back, and no live second-stage fetching. The `CI=false` profile completed package execution,
stopped its VM, destroyed its clone, and produced a 73-event typed behavior bundle. A
subscription-backed, observe-only Codex panel independently classified that bundle as malicious:
it cited the npm lifecycle execution, two credential-file open/read clusters, repeated outbound
connection attempts, and repeated sends to the local sinkhole. It explicitly did not infer which
payload bytes were sent or claim successful credential exfiltration.

The narrow file-sensor diagnostic repair was then rebuilt, physically qualified, and used in a
fresh full product run. Both `CI=false` and `CI=true` completed this time. Each profile produced a
73-event digest-bound behavior bundle; both VMs stopped, both clones were destroyed, package
execution completed, the images remained stable, no public route was exposed, and no sync-back
occurred. Subscription-backed Codex independently returned `behavior_detected` for both bundles
with no role failures. In each profile it cited lifecycle-trigger execution, two credential-file
read sequences, outbound connections, and network sends to the local sinkhole while refusing to
claim payload contents or successful credential exfiltration. The paired two-host reconciliation
is complete and preserves both deterministic and Codex behavioral detections. It remains
diagnostic-only and has no clean or admission authority until it is published through a freshly
frozen, signed evaluation campaign.

The remaining Telnyx sdist was then prepared from its sealed exact-hash custody record on the cloud
Mac without invoking WhoaThere, a VM, AI, or package code. Deterministic inspection of that exact
artifact found three behavior-eligible capability chains, including download-and-execute behavior
that matches the frozen `second_stage_fetch` regression label. The two retained Telnyx wheels were
also re-inspected without package execution using their measured diagnostic runtime. All three
Telnyx artifacts now have source-free, citation-complete metadata containing the exact artifact,
manifest, finding, file, range, and selected-byte digests needed by the narrow static verifier.

That verifier is now implemented and has been exercised directly on the approved cloud Mac against
all three retained exact artifacts. It independently reopened each archive and reproduced one
behavior-specific download-and-execute projection without running package code, starting a VM,
using AI, or accessing the network. A new exhaustive multi-run bridge also passes an end-to-end
test through the strict evaluator, including signature, denominator, and tamper checks. The
production assembler measures and pins the verifier, captures its canonical output directly,
signs the bundle, and verifies publication without accepting operator-authored projection JSON.

This is meaningful detection progress, but the public claim remains deliberately unchanged. All
four prior misses now have behavior-specific exact-artifact evidence: three independently verified
Telnyx static projections and one complete paired npm VM/Codex diagnostic. They still need to be
published together through a freshly frozen, signed, manifest-bound campaign before they can count
as a claim-bearing 4/4 result. The first Node lifecycle environment-read sensor also remains
supporting telemetry because package code could imitate its writable marker. Physical results lack
the complete dynamic evidence denominator required for clean or admission decisions. The July
restricted-malware baseline therefore remains 7/11. A strict four-sample publication can establish
a separate 4/4 prior-miss result; only the subsequent full eleven-sample rerun can establish a new
11/11 baseline. See the active
[Ultra work-chunk plan](docs/product-build-run/detection-reset-ultra-work-chunks.md), the broader
[architecture plan](docs/product-build-run/artifact-native-detection-execution-plan.md), and the
[blocker queue](docs/product-build-run/detection-blocker-queue.md).

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

- Freeze and publish one signed four-sample manifest that binds the three verified Telnyx
  projections and the complete paired `sbx` VM/Codex result. Keep the split reconciliation
  diagnostic-only until the strict producer/publisher path verifies every expected row.
- Measure the 40-artifact development benign cohort and correct practical false-malicious or
  unsupported results.
- After the signed 4/4 publication passes, stage only separately approved samples from restored
  exact-hash custody and require 11/11 behavior-specific known-regression detections.
- Complete the second-pass derived-wheel `.pth` and console-entry probes plus legacy and ZIP-sdist
  controls; unsupported paths must remain inconclusive or manual review.
- Complete the independent multi-action, multimodality dynamic verifier before allowing complete
  benign evidence to become observed-clean. The narrower positive-only static verifier and signed
  campaign assembler are already implemented; their fresh campaign invocation remains pending.
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
2. WhoaThere mirrors only the needed project files into a separate macOS VM, or stages one exact
   package artifact into a fresh disposable Linux VZ guest.
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
- DNS, connect, and send intent visible in instrumented VM telemetry, without claiming live-C2 or
  successful content-exfiltration detection
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
