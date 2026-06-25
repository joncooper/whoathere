# ADR-001: Language Selection

- Status: accepted
- Date: 2026-06-25

## Context

WhoaThere requires cross-platform native binaries, process supervision, filesystem and network control, registry protocol parsing, high-throughput HTTP serving, and security-sensitive sandbox orchestration.

## Decision

Use Rust as the default implementation language for all security-critical components:

- CLI and shims.
- Local engine.
- Sandbox runner.
- Registry adapters.
- Policy evaluator.
- Vault data plane.
- Scanner/detonator orchestrators.
- Audit event pipeline clients.

Permit Go only for an isolated high-throughput service if later benchmarks prove a material advantage and the service boundary excludes sandbox control, trust decisions, and package parsing.

## Alternatives Considered

| Alternative | Reason rejected |
| --- | --- |
| Go everywhere | Good delivery speed and HTTP ergonomics, but weaker memory-safety guarantees for parsing and lower control over security-sensitive FFI/syscall surfaces. |
| Rust CLI plus Go proxy | Viable later, but premature split increases serialization, deployment, and ownership complexity before benchmarks exist. |
| Swift for macOS endpoint | Good platform integration, but does not solve Linux parity or Vault code reuse. |
| C/C++ | Unnecessary memory-safety risk. |

## Security Impact

Rust minimizes memory-corruption risk in package parsing, policy evaluation, sandbox setup, and HTTP metadata rendering. Unsafe code is limited to platform adapter modules and requires explicit review.

## Operational Impact

One Rust workspace simplifies shared contracts, versioning, signing, and release automation. Go remains available for a bounded data-plane optimization.

## Compatibility Impact

Rust tier support covers macOS Intel/Apple Silicon, Linux x86_64/arm64, and Windows later. Platform-specific crates isolate macOS and Linux backend differences.

## Cost/Performance Impact

Rust binaries are small and predictable. Vault proxy performance must be benchmarked; Go can be reconsidered only after Rust cannot meet p95/p99 targets.

## Revisit Trigger

Revisit if load tests show Rust Vault data plane misses warm-cache SLO by more than 20% after normal optimization, or if a required platform API lacks viable Rust bindings.

