# Next Ultra Chunk: R01 Freeze the Positive-Only Four-Miss Contract

Status: complete. P07 is complete and pushed at `c1f3e08`. R01 is accepted on its dedicated branch.
R02 is ready but has not begun and must be instantiated as a separate bounded chunk.

Updated: 2026-07-18

## Accepted result

- The metadata-only validator accepts exactly four distinct artifact/profile rows.
- Canonical contract SHA-256:
  `sha256:a47b8288c14c6c1eafb3976415fdc16a24ce0b85f06f4cf2c687ee50509ee053`.
- Artifact/profile denominator SHA-256:
  `sha256:bdd99ff7ba8634dbcec7f98f442962a7c371437f9d0d3bcc9fd940f8af285c96`.
- The original complete-run profile remains byte-for-byte unchanged at
  `sha256:f8e45c1ccb191a1e621f474fb93151c6feca9b86fc4082948259019ed6e85179`.
- Twenty-one semantic mutation classes fail closed; the 22-case hermetic suite passes.
- The existing complete-run compiler and evaluator-v2 hermetic suites pass.
- Independent final verification returned `GO`.
- No package, evidence, cloud host, VM, hosted AI, malware, or private data was accessed.
- The validated positive subscore remains `0/4`; the finalized July experimental baseline remains
  `7/11`.

## Frozen user outcome

An evaluator can read and fail-closed validate one tracked, exact four-row behavior-positive
detection-subscore contract before any evidence is collected.

Primary metric: the canonical contract validates as exactly four distinct artifact/profile rows,
while every tested denominator, label, modality, threshold, claim-boundary, window-policy, or
identity-field mutation fails.

## Scope

R01 adds only:

1. a separate positive-only contract for the four artifacts missed by the July experimental run;
2. a metadata-only validator with an independently pinned semantic contract;
3. focused hermetic mutation tests; and
4. concise canonical documentation of what the contract can and cannot claim.

The existing complete-run profile remains byte-for-byte unchanged. R01 freezes semantic profile
and artifact bindings, not mutable executable or provider digests; those are frozen only in R02b
after the synthetic R02 path passes.

R01 performs no package access, archive inspection, evidence collection, scoring, cloud access,
VM start, hosted AI invocation, or malware execution.

## Frozen four-row denominator

| Row | Exact form | Positive-only profile | Required behavior-positive evidence |
| --- | --- | --- | --- |
| `mb-npm-sbx-45.0.2` | npm tgz | paired exact lifecycle VM profiles | independently verified dynamic `environment_credential_read` -> `credential_env_access` |
| `mb-telnyx-4.87.1-wheel` | wheel | measured exact-archive static capability | independently verified deterministic `download_execute_capability` -> `second_stage_fetch` |
| `mb-telnyx-4.87.2-wheel` | wheel | measured exact-archive static capability | independently verified deterministic `download_execute_capability` -> `second_stage_fetch` |
| `mb-telnyx-4.87.2-sdist` | sdist | measured exact-archive static capability | independently verified deterministic `download_execute_capability` -> `second_stage_fetch` |

Every row also binds its exact artifact SHA-256 and the corresponding complete-run profile ID for
lineage. Corpus names, hashes, labels, advisories, reputation, a generic safe block, producer prose,
or an AI-authored label cannot satisfy the subscore.

## Claim and gate semantics

- One permitted independently verified positive satisfies one row.
- A missing, invalid, inconclusive, or positive-free row is a detection miss.
- A valid positive survives incomplete sibling coverage.
- Incomplete coverage fails completion/quality and can never produce observed-clean, admission,
  release, sync-back, or overall success.
- The positive-only profile itself never creates a full-corpus-baseline or broad-detection claim.
- Detection requires 4/4, and safety independently requires every canonical safety invariant to be
  zero; `unknown` fails.
- R02b must freeze a window whose manifest predates collection and whose results, verification,
  and registry timestamps are bounded and ordered.
- R02b must freeze every named code, runtime, sensor, verifier, prompt, model, provider, policy,
  compiler, publisher, and scorer identity. A component not used is frozen as `not_used`, never
  silently omitted.

## Acceptance

1. The tracked contract validates through one documented metadata-only command and reports four
   unique rows, the exact permitted modalities, and a canonical contract SHA-256.
2. The validator rejects unknown or missing fields, row omission/duplication/reordering,
   artifact/form/profile substitution, behavior/evidence/modality widening, threshold relaxation,
   claim-boundary relaxation, window-policy relaxation, and identity-field changes.
3. The existing complete-run profile has no diff.
4. Focused tests are hermetic and use only synthetic metadata mutations.
5. Documentation says `0/4` validated positive-subscore rows until R04/R05 collect evidence and
   preserves the finalized July experimental baseline at `7/11`.
6. The branch is reviewed, committed, and pushed. Work stops before R02.

## Stop rule

At four focused hours, push a safe WIP and record the single exact blocker. Do not respond by
changing the scorer, registry, publisher, evidence schema, sensor, runtime, VM path, or cloud lab.
