# Endpoint Egress Decision Table

Registry/index steering is not a security boundary. Protected and CI contexts require independent egress enforcement so shim bypass, absolute binary invocation, nested package-manager calls, and direct source URLs cannot silently reach public sources.

## Modes

| Mode | Meaning |
| --- | --- |
| `observe` | Record only; never marketed as containment. |
| `beta_containment` | Phase 1 macOS containment candidate. Blocks high-risk claims unless backend is active. |
| `protected` | Developer protected install with local containment and policy enforcement. |
| `ci_fail_closed` | CI/high-risk mode; ambiguity blocks. |

## Default Target Decisions

| Target class | observe | beta_containment | protected | ci_fail_closed |
| --- | --- | --- | --- | --- |
| Vault/private registry | allow + record | allow + record | allow + record | allow + record |
| Public npm/PyPI direct | record | block unless policy source allows through Vault | block unless policy source allows through Vault | block |
| Direct IP public | record | block unless exact policy allow | block unless exact policy allow | block |
| RFC1918/private network | record | block unless exact project policy | block unless exact project policy | block |
| Localhost | record | block unless explicit local dev policy | block unless explicit local dev policy | block |
| Cloud metadata IPs | record + high severity | block | block | block |
| DNS to non-approved resolver | record | block | block | block |
| DoH/DoT | record | block | block | block |
| Git SSH/HTTPS source | record | policy-gated, warn/manual_review for unknown | policy-gated, manual_review for unknown | block unless allowlisted source+digest |
| Arbitrary HTTPS during lifecycle/build | record | block or controlled recorded egress by evidence profile | block or controlled recorded egress by evidence profile | block or controlled detonation egress only |

## Workflow Decisions

| Workflow phase | Allowed network shape | Failure behavior |
| --- | --- | --- |
| Artifact metadata resolution | Vault/private registry only in protected/CI mode. | Deny/fail closed if package manager resolves public source directly. |
| Artifact download | Vault CAS or approved private registry only. | Deny/fail closed on public direct URL unless source policy explicitly admits it. |
| npm lifecycle scripts | No network by default; controlled recorded egress only in detonation. | Block in CI/high-risk; developer prompt only for non-secret low-risk policy. |
| PEP 517 build dependencies | Vault/policy-approved sources only. | Unknown build requirement triggers admission/manual review; no public fallback. |
| `npx`/`npm exec` | Treat as high-risk transient execution. | CI requires allow verdict or scoped break-glass; developer mode prompts or blocks by policy. |
| `pip download` | Vault/private index route only. | Deny public fallback for internal namespace and protected mode. |
| Editable/VCS/direct URL | Explicit source policy and digest/ref pin required in CI. | Unknown source blocks or manual_review; no warn-only CI. |
| Nested npm/pip invocation | Must inherit containment, egress policy, and correlation ID. | Bypass signal; high-risk/CI fails closed. |

## Backstop Requirements

- `whoathere doctor` must verify PATH order, real binary discovery, shim health, policy snapshot validation, Vault route, and egress enforcement.
- Protected workspace setup must include a network-level or proxy-level deny rule for direct public registry/index traffic in CI/high-risk contexts.
- A detected bypass is not merely telemetry in `ci_fail_closed`; it becomes a policy violation and blocks.
- First-execution bypass is unacceptable for CI/high-risk. The implementation plan must prove direct egress is blocked before package-manager execution begins.

