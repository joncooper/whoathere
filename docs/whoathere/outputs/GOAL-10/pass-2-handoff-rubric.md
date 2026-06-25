# Pass 2 Rubric: Downstream Execution Handoff

## Purpose

Evaluate whether the phase goals and execution prompts carry the remediation constraints into future `/goal` runs without forcing the next agent to rediscover GOAL-09.

## Criteria

| Criterion | Weight | Passing standard |
| --- | ---: | --- |
| GOAL-09 as mandatory input | 25 | Every downstream phase goal that touches remediated areas lists GOAL-09 artifacts as inputs. |
| Phase-specific ownership | 25 | Phase goals match GOAL-09 primary-owner test assignments and do not overclaim tests. |
| Research contract propagation | 20 | Phase 3/4 explicitly own the minimum allow-verdict evidence research where relevant. |
| macOS beta/GA handoff | 15 | Phase 2 distinguishes beta containment hardening from GA containment graduation. |
| Operator/admin handoff | 15 | Future goal loops know minimum control-plane API/UX is required even if dashboard polish is deferred. |

## Pass Threshold

Minimum acceptable score: 90/100. Any phase goal that omits GOAL-09 despite depending on remediated constraints requires improvement.

