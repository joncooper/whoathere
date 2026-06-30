# Pass 1 Rubric: Readiness And Completion Semantics

## Purpose

Evaluate whether the package can distinguish document existence from planning readiness, research-required gaps, validation-pending decisions, and implementation readiness.

## Criteria

| Criterion | Weight | Passing standard |
| --- | ---: | --- |
| Readiness tier present | 30 | Every completion record declares a readiness tier. |
| Tier matches evidence | 25 | No goal claims `implementation_ready` while schemas, allow-verdict research, control-plane API/UX, or platform validation remain open. |
| Follow-up blocking semantics | 20 | Blocking follow-ups are labeled as blocking for the correct claim, not for the whole planning package. |
| Summary consistency | 15 | Final summary and completion records use the same readiness vocabulary. |
| Auditability | 10 | A reviewer can verify the package state with simple file/search checks. |

## Pass Threshold

Minimum acceptable score: 90/100. Any missing readiness tier is an automatic improvement item.

