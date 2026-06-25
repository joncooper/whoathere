# Quality Verification Manifest

Run these commands from `/Users/jdc/src/whoathere`.

| Check | Command | Proves |
| --- | --- | --- |
| GOAL-10 pass artifact coverage | `for p in 1 2 3; do for kind in rubric evaluation improvement-plan execution-notes verification; do find docs/whoathere/outputs/GOAL-10 -maxdepth 1 -name "pass-${p}-*${kind}*.md" -print -quit; done; done` | Every requested pass has the required artifact classes. |
| GOAL completion records | `find docs/whoathere/outputs -name completion-record.md -print | sort` | GOAL-01 through GOAL-10 have completion evidence. |
| Readiness tiers | `rg -n "Readiness tier" docs/whoathere/outputs/GOAL-*/completion-record.md` | Completion records declare readiness tiers. |
| GOAL-09 handoff | `rg -n "GOAL-09" docs/whoathere/outputs/GOAL-07/phase-*.md` | All phase goals carry remediation inputs/constraints. |
| Stale overclaim phrases | `rg -n "Blocking Ambiguity|Global done definition|specified for planning|developer_on_outage: warn$|Owns AT-001 through AT-009|macOS VM-backed strong isolation path|All malicious behavior covered" docs/whoathere` | Finds old claims that should not reappear. Expected: no problematic matches; retrospective mentions in GOAL-09/GOAL-10 are acceptable only when describing fixed prior state. |
| ASCII | `rg -n -P "[^\\x00-\\x7F]" docs/whoathere README.md` | Docs remain ASCII-only. Expected: no matches. |
| GOAL-10 discoverability | `rg -n "GOAL-10|Quality Hardening" docs/whoathere/README.md docs/whoathere/outputs/final-goal-pack-execution-summary.md` | README and final summary expose GOAL-10. |

## Interpretation Rules

- Search commands returning no matches are successful only when the expected result says no matches.
- Stale-phrase matches are allowed only if the surrounding sentence explicitly describes a prior state fixed by a later pass.
- Verification proves planning-package consistency, not product implementation.

