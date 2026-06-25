# Repo Structure Plan

## Proposed Workspace

```text
whoathere/
  crates/
    whoathere-cli/
    local-engine/
    sandbox-runner/
    registry-adapters/
    vault-data-plane/
    scan-detonation-workers/
    policy-core/
    audit-core/
    contracts/
  infra/
    aws/
    cloudflare/
    hybrid/
  fixtures/
    npm/
    pypi/
    mixed/
  docs/
    adr/
    architecture/
    operations/
  tests/
    integration/
    e2e/
    performance/
```

## Crate Rules

- `contracts` owns shared types for policy, audit, scanner jobs, admission API, and registry coordinates.
- `policy-core` is pure Rust and usable by endpoint and Vault.
- `registry-adapters` contains ecosystem-specific parsing/rendering with fuzz tests.
- `sandbox-runner` exposes one trait with Linux and macOS implementations.
- Cloud provider code lives outside core crates unless required for a narrow interface.

## Build And Release

- Use Rust stable.
- Produce signed macOS universal binaries and Linux x86_64/arm64 binaries.
- Container images for Vault use minimal distroless or Wolfi-style base images after security review.
- CI runs unit, integration, fixture, fuzz, and cross-compilation checks.

