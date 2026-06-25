# Product Build Run Pass 1: Plan Executability

## Scope

Reviewed the granular build plans for executable next slices:

- Phase 1 local CLI and endpoint contracts.
- Phase 2 isolation primitives that can be modeled safely before OS sandbox work.
- Phase 3 Vault admission, generation, and registry facade.
- Phase 4 evidence profiles and static detector.

## Findings

| Slice | Finding | Risk |
| --- | --- | --- |
| Phase 1 CLI | Existing scaffold lacked command classification, exit-code constants, and shim manifest output. | Wrappers could not make deterministic fail-closed decisions. |
| Phase 2 isolation | Egress and cleanup were plan-only. | Later sandbox work could miss public-registry denial and cleanup ownership. |
| Phase 3 Vault | Promotion model was documented but not executable. | A future serving path could accidentally serve unpromoted artifacts. |
| Phase 4 detonation | Evidence profiles existed only in markdown. | Allow decisions could drift from mandatory evidence requirements. |

## Improvements Made

- Added `CommandClassification`, `ExitCode`, npm/pip workflow classifier, and bypass signal handling in `whoathere-core`.
- Added dry-run shim manifest rendering and richer `protect` output in `whoathere-cli`.
- Added egress policy evaluator and cleanup lease model in `whoathere-sandbox`.
- Added `whoathere-evidence`, `whoathere-vault-api`, `whoathere-admission`, `whoathere-registry`, and `whoathere-detector` crates.

## Validation

- `cargo test --manifest-path whoathere/Cargo.toml` passed after fixing a `python -m pip install` classifier regression caught by tests.
- No npm, pip, Python build backend, Node script, public registry, or malware fixture execution occurred.
