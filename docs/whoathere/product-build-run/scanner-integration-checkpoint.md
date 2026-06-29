# WhoaThere Scanner Integration Checkpoint

Date: 2026-06-28

## Summary

WhoaThere now has a functional scanner evidence layer for the macOS local beta. The scanner layer
can list available tools, explain the bootstrap plan, run core scanner adapters against a local
workspace, and return normalized redacted results.

The scanner layer does not replace the macOS VM. A scanner result cannot authorize package-manager
execution or file copy-back by itself.

## Implemented Behavior

- Added `whoathere scanners list [--json]`.
- Added `whoathere scanners bootstrap-plan [--json]`.
- Added `whoathere scanners run --workspace <path> [--ecosystem auto|npm|pypi] [--state-dir <dir>] [--timeout-seconds <n>] [--execute] [--json]`.
- Added schema `whoathere.external_scanner_run.v1`.
- Added normalized statuses: `passed`, `findings`, `unavailable`, `not_applicable`, `error`, and `timed_out`.
- Added scanner bootstrap script: `scripts/whoathere-bootstrap-scanners.sh`.
- Added scanner smoke script: `scripts/whoathere-scanner-integration-smoke.sh`.
- Added doctor fields for scanner bootstrap and future public-package auto-trust readiness.
- Tightened `scanner_public_package_auto_trust_ready` so it requires all core scanners to be
  available and a valid scanner bootstrap receipt with matching core counts and ready core scanner
  records. When current scanner versions are observable, they must match the bootstrap receipt.
  Finding scanner binaries or a malformed/stale receipt alone is not enough to claim future
  public-package readiness.
- Fixed GuardDog and pip-audit `uvx` fallback execution so fallback runs as `uvx guarddog ...`
  or `uvx pip-audit ...` instead of treating `uvx` as if it were the scanner binary.

## Adapter Scope

Core executed adapters:

- GuardDog for malicious package static indicators.
- OSV-Scanner for known vulnerability evidence.
- pip-audit for pinned Python requirements only.
- Syft for SBOM evidence.
- Grype for SBOM vulnerability evidence.

Report-only adapters:

- Trivy.
- Scorecard.

## Security Boundaries

- Scanner output is summarized and digested; raw stdout/stderr is not included in JSON.
- Scanner bootstrap readiness distinguishes receipt presence from receipt validity. Malformed
  bootstrap receipts, missing core scanner records, mismatched core counts, or stale scanner
  version records keep future public-package readiness false.
- Executed scanner receipts include state-local `scanner_receipt_auth` when `--state-dir` is
  supplied. Clean scanner receipts without this auth tag are report-only and cannot satisfy
  package-risk auto-sync evidence.
- Package-risk accepts clean scanner receipts only when they were actually executed, match the
  current workspace digest, are state-authenticated, are not stale, include every expected core
  scanner record, include valid full SHA-256 executable digests, have a consistent runnable core
  scanner count, and show at least one core scanner passed. Signed but malformed clean receipts are
  treated as invalid evidence.
- Scanner binaries are resolved from the WhoaThere scanner cache or trusted system binary
  directories. Scanner binaries inside the assessed workspace are refused.
- Workspace paths, canaries, and token-like material must not appear in scanner JSON output.
- pip-audit skips unpinned, direct URL, VCS, editable, nested, and otherwise resolution-dependent
  requirements instead of resolving on the host.
- A scanner run against an unknown workspace/ecosystem cannot produce `scanner_clean=true`, even if
  generic filesystem scanners pass.
- Missing scanners are visible but do not block the current local-only macOS beta.
- Missing or dirty scanner evidence must block any future public package auto-trust claim.
- Scanners cannot override VM isolation, canary checks, strict file copy-back rules, or manual
  review for binary/native/direct/VCS/editable package types.

## Validation Commands

Run after scanner integration changes:

```sh
scripts/whoathere-bootstrap-scanners.sh
scripts/whoathere-scanner-integration-smoke.sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
rg -n "[^[:ascii:]]" docs/whoathere/product-build-run scripts whoathere/crates
```

Optional real-tool smoke after bootstrap:

```sh
WHOATHERE_SCANNER_REAL_SMOKE=1 scripts/whoathere-scanner-integration-smoke.sh
```

## Morning Pressure-Test Checklist

- Malicious npm install script fixture.
- Python build hook fixture.
- Known-vulnerable pinned Python requirement.
- Unpinned Python requirement.
- Direct URL dependency.
- Git/VCS dependency.
- Binary wheel or native marker.
- Scanner outage.
- Scanner timeout.
- Real-tool output redaction.
- Verify `doctor --json` still reports `scanner_release_blocking=false` for the local-only beta.
- Verify future public-package auto-trust remains blocked unless scanner evidence is clean and
  other VM/copy-back evidence is also clean.
