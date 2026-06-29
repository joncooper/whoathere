# WhoaThere Package Risk Gates Checkpoint

Date: 2026-06-29

## Summary

WhoaThere now has local package risk gates for the macOS beta. The gates remember approved clean
package evidence, prefer last-known-good versions for unpinned npm/pip/uv specs when possible,
apply a 7 day fresh-release cooldown, require clean scanner evidence for public auto-sync
candidates, flag suspicious package diffs, and feed package-risk receipts into the VM release-plan
model.

This does not claim comprehensive package safety. Package risk gates are evidence. They do not
replace the macOS VM, scanners, canary checks, strict sync-back rules, or manual review.

## Implemented Behavior

- Added `whoathere package-risk assess --workspace <path> [--ecosystem auto|npm|pypi|uv] [--state-dir <dir>] [--json]`.
- Added `package-risk assess --scanner-receipt <path>` to consume normalized `scanners run --execute --json` evidence.
- Added opt-in local model review through `package-risk assess --ai-review --ai-provider ollama --ai-model <model>`.
- Added `whoathere package-risk history --package <name> --ecosystem <npm|pypi|uv> [--state-dir <dir>] [--json]`.
- Added `whoathere package-risk approve --receipt <path> --reason <text> [--state-dir <dir>] [--json]`.
- Added append-only local package memory under `<state-dir>/package-risk/package-risk-evidence.jsonl`.
- Added per-assessment receipts under `<state-dir>/package-risk/receipts/`.
- Added `vm release-plan --package-risk-receipt <path>` to derive scanner, freshness, and diff gates from package-risk evidence.
- Added `doctor --json` package-risk readiness fields.
- Added deterministic package-risk and real-world-inspired attack harness scripts.
- Added `WHOATHERE_SCANNER_CACHE_DIR` for deterministic scanner outage/timeout tests.

## Security Boundaries

- Package-risk JSON does not include raw package source, raw scanner output, canaries, tokens, or
  host secret paths.
- Local model review is advisory evidence only. It runs through a local Ollama command when
  requested, receives bounded redacted snippets, and records only status, reason codes, timing, and
  prompt/output hashes. Raw prompts and model output are not stored.
- A clean local model result cannot authorize execution, copy-back, or bypass freshness, diff,
  scanner, VM, or package-class gates. Requested model findings, timeout, error, or provider
  unavailability force manual review.
- Scanner receipts are normalized evidence. Clean scanner receipts must be executed scanner runs
  bound to the assessed workspace digest. Dirty, unreadable, invalid, not-executed, missing, or
  wrong-workspace scanner receipts force manual review and override operator-provided
  `--scanner-clean`.
- Public npm/PyPI auto-sync candidates require clean scanner evidence. Missing scanner evidence is
  manual review, not a clean result.
- Local approval only accepts package-risk receipts that were already clean auto-sync candidates;
  manual-review, deny, scanner-missing, scanner-dirty, or incomplete receipts cannot seed
  last-known-good history.
- Reputation is a warning and reason-code signal, not an allow rule.
- New lifecycle scripts, `.pth` files, native/binary markers, direct URLs, VCS/editable sources,
  platform-specific payloads, and credential/network-looking code block auto-sync.
- Binary wheels, native extensions, sdists/PEP 517 builds, direct URLs, VCS/editable installs, and
  unknown package classes remain manual-review or deny by default.
- API-compatible malicious packages are covered only by static/API-use-inspired fixtures and VM
  import/use probes where available; runtime application protection remains out of scope.

## Validation Commands

```sh
scripts/whoathere-package-risk-smoke.sh
scripts/whoathere-real-world-attack-harness.sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli package_risk --quiet
```

Full validation for this slice should also run:

```sh
scripts/whoathere-bootstrap-scanners.sh
scripts/whoathere-scanner-integration-smoke.sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
rg -n "[^[:ascii:]]" docs/whoathere/product-build-run scripts whoathere/crates
```

## Morning Pressure-Test Checklist

- Validate last-known-good substitution for npm, pip, and uv unpinned specs.
- Validate fresh-release cooldown with real registry metadata when online enrichment is added.
- Validate suspicious diffs against real previous package artifacts.
- Validate binary wheel, native extension, direct URL, VCS, and editable cases remain non-auto-sync.
- Run the real-world attack harness after scanner bootstrap and again with fake scanner outage and
  timeout paths.
- Confirm package-risk receipts cannot make `vm release-plan` auto-sync without clean VM evidence,
  clean scanner evidence, a clean package-risk verdict, and matching package class.
- Run `package-risk assess --ai-review --ai-provider ollama --ai-model gemma4:latest` on a known
  suspicious fixture and verify only normalized review evidence is recorded.
- Confirm docs still avoid claiming universal malware detection or runtime application protection.
