# Minimum Allow-Verdict Research Contract

## Decision

Exact allow-verdict evidence by ecosystem, artifact type, platform, and source type is a core research question for the downstream goal loops. Phase 3 may promote cold-miss artifacts in production only after this contract is answered for the artifact class being promoted.

## Required Output From Downstream Goals

The Phase 3 and Phase 4 loops must produce a table with this shape:

| Ecosystem | Artifact/source type | Required static evidence | Required dynamic evidence | Required provenance/reputation evidence | Platform coverage | Failure behavior |
| --- | --- | --- | --- | --- | --- | --- |
| npm | registry tarball | TBD by research | TBD by research | TBD by research | TBD by research | deny/manual_review/503, never partial allow |
| npm | native extension | TBD | TBD | TBD | TBD | deny/manual_review/503 |
| npm | git/tarball/direct URL | TBD | TBD | TBD | TBD | manual_review or deny by default |
| PyPI | wheel | TBD | TBD | TBD | TBD | deny/manual_review/503 |
| PyPI | sdist/PEP 517 | TBD | TBD | TBD | TBD | deny/manual_review/503 |
| PyPI | editable/VCS/direct URL | TBD | TBD | TBD | TBD | manual_review or deny by default |

## Mandatory Research Questions

- Which npm lifecycle scripts must be executed or suppressed in detonation before allow?
- Which PyPI build paths must run for PEP 517 backends, sdists, wheels, and native extensions?
- When is import-time detonation mandatory before allow?
- What evidence is sufficient for packages with platform selectors, optional dependencies, extras, markers, wheel tags, npm `os`/`cpu`, or generated build backends?
- How are delayed, CI-gated, hostname-gated, and sandbox-fingerprinting payloads represented?
- Which source types are never auto-allowable and always require manual review?
- What is the maximum acceptable scanner/detonator timeout before `manual_review` or `503`?

## Hard Rules Before Research Completes

- Partial evidence cannot produce `allow`.
- Scanner or detonator infrastructure failure cannot produce `allow`.
- Unknown source type cannot produce `allow` in CI/high-risk mode.
- A package may be warm-cache servable only for artifact classes whose minimum allow-verdict row is complete and passing.
- Break-glass cannot create a durable allow verdict for unknown or unscanned artifacts.

