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
- Added `whoathere scanners run --workspace <path> [--ecosystem auto|npm|pypi] [--timeout-seconds <n>] [--execute] [--json]`.
- Added schema `whoathere.external_scanner_run.v1`.
- Added normalized statuses: `passed`, `findings`, `unavailable`, `not_applicable`, `error`, and `timed_out`.
- Added scanner bootstrap script: `scripts/whoathere-bootstrap-scanners.sh`.
- Added scanner smoke script: `scripts/whoathere-scanner-integration-smoke.sh`.
- Added doctor fields for scanner bootstrap and future public-package auto-trust readiness.

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
- Workspace paths, canaries, and token-like material must not appear in scanner JSON output.
- pip-audit skips unpinned, direct URL, VCS, editable, nested, and otherwise resolution-dependent
  requirements instead of resolving on the host.
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
