# WhoaThere Agent Orientation

This file orients new Codex sessions working in this repository. Treat it as a handoff note, not as
a replacement for reading the code and the current docs.

## Current Product State

WhoaThere is currently best described as a macOS local containment and package-workflow admission
preview for Python and Node development.

Credible claim today:

- Supported package setup workflows can be run away from the host in a macOS VM.
- Copy-back is deny-by-default and evidence-bound.
- The July 1, 2026 actual-malware lab run held the safety invariants: 0 host executions,
  0 sync-backs, 0 unsafe allows, and 0 restricted-material leaks in sanitized evidence.

Do not claim yet:

- Broad supply-chain malware detection.
- Low false-positive or low-friction developer experience.
- Live C2 or network-exfiltration detection.
- Arbitrary npm/PyPI package safety.
- Enterprise package-proxy or CI enforcement readiness.

The actual-malware run produced 7 of 11 behavior detections, or 63.6%, below the 85-90% detection
gate. The right summary is: containment worked; detection coverage needs engineering follow-up.

## Start Here

Read these first:

- `README.md`
- `docs/product-build-run/whoathere-actual-malware-experimental-run-2026-07-01.html`
- `docs/product-build-run/actual-malware-evaluation.md`
- `docs/product-build-run/macos-local-release-readiness.md`
- `docs/product-build-run/macos-local-beta-cli-guide.md`

The local restricted evidence snapshot, when present, is under:

```text
.whoathere/remote-evidence-snapshots/whoathere-actual-malware-2026-07-01-sanitized/
```

That directory is gitignored. Do not stage it. Do not move raw malware, quarantine archives, VM
disks, packet captures, or full telemetry into tracked paths.

## Actual Malware Handling Rules

- Do not download, unpack, execute, or inspect raw malware unless the user explicitly asks and the
  approved lab workflow is being used.
- Do not run malware locally in this workspace.
- Do not use Docker as a detonation environment. The corpus-lab container is acquisition/custody
  support only.
- Do not enable `--sync-back` for malware.
- Do not contact live C2 or fetch live second stages.
- Use only sanitized evidence in tracked docs.
- Keep MalwareBazaar keys, sudo passwords, canaries, and provider details out of commits.

## Current Highest-Leverage Engineering Work

The failed detection gate points at specific product gaps:

- PyPI wheels need first-class artifact metadata parsing from `.dist-info/METADATA`, `WHEEL`,
  `RECORD`, and entry points.
- PyPI sdists need root normalization before package-risk and VM planning.
- VM workflows need direct wheel install and nested sdist install support.
- npm package-artifact detonation needs lifecycle coverage that can exercise CI-gated behavior
  under canary envs.
- Benign controls need to be run and scored before any usability or false-positive claim.

Keep the scorer strict. Do not count corpus labels as detections; only behavior-specific evidence
should upgrade a safe block into a behavior-detected result.

## Useful Commands

Core checks:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
```

Focused smoke tests:

```sh
scripts/whoathere-package-risk-smoke.sh
scripts/whoathere-scanner-integration-smoke.sh
scripts/whoathere-real-world-attack-harness.sh
scripts/whoathere-actual-malware-harness-selftest.py
```

The actual-malware scripts are for controlled lab use:

```text
scripts/whoathere-corpus-lab.sh
scripts/whoathere-malwarebazaar-bulk-acquire.sh
scripts/whoathere-build-scaleway-staging-bundle.sh
scripts/whoathere-scaleway-host-preflight.sh
scripts/whoathere-scaleway-step5.sh
scripts/whoathere-scaleway-steps6-8.sh
```

Do not run the Scaleway scripts casually. They assume an approved disposable lab host and restricted
sample custody.

## Documentation Rules

- Preserve the distinction between safety and detection quality.
- Call older phase/status docs historical if they predate the final July 1 campaign.
- Link to the final experimental report for the current result.
- Use sanitized hashes, sample IDs, verdicts, and claim boundaries.
- Do not include raw malware bytes, full logs with secrets/canaries, host-private paths beyond
  already sanitized evidence references, or acquisition credentials.

## Git Hygiene

The worktree may contain user or generated changes. Do not revert files you did not change unless
the user explicitly asks.

Before committing:

- Inspect `git status --short`.
- Stage only intentional files.
- Check for secrets with `rg` before commit.
- Confirm `.whoathere/` and `.env` remain ignored.
