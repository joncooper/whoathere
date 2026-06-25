# Roadmap Dependency Graph

```mermaid
flowchart TB
  G1["GOAL-01 Scope/Threat Model"] --> G2["GOAL-02 System Architecture"]
  G1 --> G3["GOAL-03 Endpoint"]
  G1 --> G4["GOAL-04 Vault"]
  G2 --> G3
  G2 --> G4
  G3 --> G5["GOAL-05 Policy/Audit"]
  G4 --> G5
  G4 --> G6["GOAL-06 Detection"]
  G5 --> G6
  G5 --> G8["GOAL-08 Ops/Privacy"]
  G4 --> G8
  G6 --> G8
  G1 --> P1["Phase 1 CLI"]
  G2 --> P1
  G3 --> P1
  G5 --> P1
  P1 --> P2["Phase 2 Isolation"]
  G4 --> P3["Phase 3 Vault"]
  G5 --> P3
  G8 --> P3
  P2 --> P3
  P3 --> P4["Phase 4 Detonation"]
  G6 --> P4
```

## Hard Prerequisites

- Phase 1 requires GOAL-01, GOAL-02, GOAL-03, GOAL-05, and GOAL-08 decisions.
- Phase 2 requires Phase 1 endpoint skeleton and GOAL-03 backend decisions.
- Phase 3 requires GOAL-04, GOAL-05, GOAL-08, and Phase 1 CI integration shape.
- Phase 4 requires GOAL-06 and Phase 3 Vault admission path.

## Soft Prerequisites

- Cloudflare hybrid can wait until after AWS Vault MVP.
- macOS beta containment can harden in Phase 2 while Phase 1 ships explicit beta or telemetry-only semantics.

## Hidden Work Check

No phase depends on an unnamed product-scope decision. Open items are implementation details or explicitly named future goals.
