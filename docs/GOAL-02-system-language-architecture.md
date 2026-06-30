# GOAL-02: System And Language Architecture

## Objective

Create the system architecture and language-selection ADRs for WhoaThere CLI, sandbox supervisor, Vault proxy, scanners, and control-plane-facing services.

## Required Architecture Baseline

Default to Rust for the CLI, local engine, sandbox runner, registry adapters, policy evaluator, and security-sensitive proxy components because the product requires memory safety, small cross-platform native binaries, careful process control, filesystem handling, and syscall/FFI work.

Permit Go only where a specific child plan proves a better fit, such as a high-throughput HTTP data-plane component with clear isolation from security-critical parsing and sandbox control.

## Required Module Boundaries

- `whoathere-cli`: user-facing commands, shims, diagnostics, config, local status, and auth.
- `local-engine`: package-manager command classification, local policy evaluation, audit event creation, and sandbox orchestration.
- `sandbox-runner`: Linux and macOS isolation backends behind one internal interface.
- `registry-adapters`: npm registry and PyPI Simple API compatibility, metadata normalization, lockfile/source parsing.
- `vault-data-plane`: registry proxy endpoints, metadata rendering, content streaming, cache lookup, and admission enforcement.
- `scan-detonation-workers`: static analysis, sandbox execution, telemetry capture, verdict generation.
- `policy-service`: policy storage, evaluation, overrides, tenant/project identity, and distribution.
- `audit-event-pipeline`: append-only audit events, evidence bundles, retention, and search/export.

## Required Decisions

- Rust workspace layout and crate boundaries for shared CLI/proxy code.
- Whether Vault data-plane is Rust-only, Go-only, or mixed.
- Serialization formats for internal job and audit contracts.
- Error and exit-code conventions shared by CLI, shims, and CI.
- Packaging/distribution model for macOS and Linux binaries.
- How unsafe Rust, FFI, and platform-specific code are reviewed and constrained.

## Required Deliverables

- `ADR-001-language-selection.md`: Rust versus Go decision with component-specific outcomes.
- `system-context.md`: C4-style context and container diagrams in Mermaid.
- `module-boundaries.md`: ownership, responsibilities, input/output contracts, and trust boundaries.
- `repo-structure-plan.md`: proposed workspace layout for implementation.
- `platform-support-plan.md`: macOS Intel, macOS Apple Silicon, Linux x86_64, Linux arm64, and Docker support matrix.

## Acceptance Criteria

- The architecture has no single unowned subsystem.
- Every public interface listed in `interfaces-and-contracts.md` has an owning module.
- Security-critical parsing and sandbox control have a memory-safe implementation plan.
- The plan explains why package-manager forking is not the default strategy.
- The plan defines how Windows is kept out of MVP without blocking future expansion.

## Exit Gate

Do not start implementation planning until ADR-001 names the language for each component and `module-boundaries.md` maps all interfaces to owners.

## Suggested Subagents

- Rust systems reviewer.
- Go/cloud proxy performance reviewer.
- Cross-platform release engineering reviewer.

