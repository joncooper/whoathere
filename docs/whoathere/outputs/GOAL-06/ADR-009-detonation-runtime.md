# ADR-009: Detonation Runtime

- Status: accepted
- Date: 2026-06-25

## Context

Detonation must execute untrusted install/build/import behavior with strong isolation and evidence capture across Linux CI and macOS developer contexts.

## Decision

Use Linux containers/microVM-capable workers for primary Vault detonation, with macOS VM workers for macOS-specific artifacts where required. Linux detonation runs in isolated ephemeral workers with no internal network route and controlled recorded egress. macOS detonation is lower throughput and used only when policy requires macOS coverage.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Containers only for all platforms | Cannot represent macOS-specific behavior. |
| Full VMs for all detonation | Strong but expensive and slower for default Linux path. |
| Static analysis only | Insufficient for install/build/import behavior. |
| WASM | Cannot run arbitrary package manager/native toolchains. |

## Security Impact

Ephemeral workers reduce persistence. No internal network route and blocked metadata service prevent lateral movement.

## Operational Impact

Requires worker image management, queue scaling, evidence storage, and timeout/circuit breaker policy.

## Compatibility Impact

Linux packages get broad coverage; macOS-specific packages require separate capacity.

## Cost/Performance Impact

Linux workers are the default for cost/performance. macOS VM workers are used selectively.

## Revisit Trigger

Revisit if container escape risk, platform coverage, or macOS throughput fails acceptance tests.

