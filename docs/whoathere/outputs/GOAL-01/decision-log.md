# Decision Log

| Decision | Outcome | Rationale | Deferred follow-up |
| --- | --- | --- | --- |
| First vertical slice | Vault-backed endpoint and CI flow | Exercises local interception, policy, Vault admission, audit, and fail-closed behavior end to end. | Phase 1 may implement local-only subset first but must preserve Vault contracts. |
| Endpoint platforms | macOS and Linux in parallel | User requirement; Linux provides strongest isolation, macOS validates laptop workflow. | Windows after Phase 2. |
| Enforcement posture | CI fail closed; developer warning only by policy | Prevents delivery pressure from bypassing controls. | Admin UX in later control-plane plan. |
| Runtime scope | Import-time detonation in scope; full runtime protection out | Captures common package activation while avoiding unbounded runtime EDR scope. | Runtime controls as future product line. |
| Primary interception | PATH shims plus config steering | Preserves standard tooling without forking package managers. | Backstop telemetry research. |
| Primary cloud posture | Compare AWS, Cloudflare, hybrid; bias AWS for VPC detonation | AWS has stronger mature private-network primitives; Cloudflare remains candidate for edge/cache/Zero Trust. | Final ADR-011. |

## Deferred Questions Converted To Follow-Up Goals

- Validate macOS beta-containment backend and later GA containment path in GOAL-03/Phase 2.
- Determine final Vault deployment recommendation in GOAL-04.
- Determine policy distribution model in GOAL-05.
- Determine detonation runtime in GOAL-06.
