# ADR-004: macOS Isolation Backend

- Status: accepted
- Date: 2026-06-25

## Context

macOS does not provide a supported general-purpose equivalent to Linux namespaces/seccomp for arbitrary CLI package-manager executions. Apple Silicon and developer-tool compatibility make overclaiming native sandbox controls risky.

## Decision

Use VM-backed isolation as the macOS strong-control candidate. Phase 1 macOS is beta containment, not GA containment. Endpoint Security is used for attribution, telemetry, and partial control. Seatbelt/private sandbox profiles are research-only and not a dependable product foundation.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Endpoint Security only | Good telemetry/control plane but not a complete sandbox. |
| Seatbelt profiles | Undocumented/private behavior and brittle product foundation. |
| pf/Network Extension only | Network control without filesystem/process isolation. |
| No macOS isolation | Fails laptop blast-radius goal. |

## Security Impact

VM isolation gives the cleanest boundary for untrusted install/build behavior. Host project sharing must be narrow, explicit, and revertible. Endpoint Security records missed invocations and suspicious host-side process/file events.

## Operational Impact

Requires signed/notarized helper components and VM image lifecycle. Developer UX must explain first-run setup and resource use.

## Compatibility Impact

Filesystem sharing, symlinks, file ownership, native artifacts, and Apple Silicon architecture matching need compatibility tests. Phase 1 may expose `macOS beta containment` only when the VM path is active and policy permits beta mode. If VM mode cannot transparently install into host projects, Phase 1 must label macOS as telemetry/interception only and fail closed for CI/high-risk workflows that require containment. Phase 2 owns GA containment validation.

## Cost/Performance Impact

Mac VM cold start is expected to be materially slower than Linux sandbox startup; warm VM pool and per-project cache are required for usability.

## Revisit Trigger

Revisit only if a supported Apple API provides enforceable process/filesystem/network confinement for arbitrary CLI tools with better compatibility than VM isolation.
