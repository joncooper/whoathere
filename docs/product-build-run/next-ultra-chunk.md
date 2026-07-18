# Next Ultra Chunk: P04 Four Prior Misses as Product Reports

Status: complete. P05 remains queued and was not started in this chunk.

Parent plan: [Detection Reset Ultra Work Chunks](detection-reset-ultra-work-chunks.md)

## Immutable execution contract

```text
Model: GPT-5.6 Codex
Reasoning effort: Ultra
Start commit: 8d917a7
Branch: codex/p04-four-miss-reports
Timebox: 1-3 active hours; hard stop at 3 hours
Primary metric: exactly four unique, digest-bound sanitized projections render behavior-specific
                BLOCK reports through the production saved-report command
Forest checks: 60 minutes and after two failed approaches
End rule: push accepted work or a clearly marked WIP reproduction; do not begin P05
```

## User-facing outcome

A reader receives four compact, source-free product reports explaining why all four artifacts that
the July experiment missed are now blocked. The report says `diagnostic 4/4` while preserving the
finalized July experimental baseline of `7/11`.

This is product presentation of existing diagnostic evidence. It is not a new signed evaluation,
does not alter the finalized baseline, and grants no clean, installation, admission, release, or
sync-back authority.

## Frozen exact inputs

Only these four already-produced, local sanitized projections are in scope. The projection bytes
remain under ignored restricted-evidence custody and must not be committed.

| Input | Artifact SHA-256 | Sanitized report SHA-256 | Required derived product behavior |
| --- | --- | --- | --- |
| Telnyx 4.87.1 wheel | `sha256:7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9` | `sha256:b662269261553d071426807107cb226072a24c03491acccd32b4091b44cf5f43` | `download_execute_capability` |
| Telnyx 4.87.2 wheel | `sha256:cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3` | `sha256:11770b7fd13aa752019447e59d287eb3c12caed4ddf5b68663d69dbc41646fd8` | `download_execute_capability` |
| Telnyx 4.87.2 sdist | `sha256:a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5` | `sha256:3c784119fef8532848d2906a1cd476ef2dc9006d83b09ab7e37bc04dde92601c` | `download_execute_capability` |
| npm sbx 45.0.2 | `sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933` | `sha256:bc09a308462940012d9060b54a46ff7568ee94d04a5ccb2d10a3faeca1a5e452` | current eligible sensitive-path, exfiltration, and environment-to-process capabilities |

The expected identities and behavior names are acceptance checks only. They must never create or
upgrade a verdict. Each `BLOCK` must be re-derived from the projection's typed, digest-bound,
behavior-eligible observations.

## Demonstrated compatibility gap

The four files are producer-defined sanitized projections of
`whoathere.exact_artifact_inspection.v1`, not complete P03 reports. They intentionally omit source
coordinates, CAS keys, package identity, scenario intents, selected bytes, and package source, and
add explicit sanitization flags and source-receipt bindings. The current strict P03 decoder
correctly rejects them as a different closed shape.

P04 may add one strictly separated decoder for this existing projection shape behind the same
command:

```text
whoathere report render <sanitized-report.json> --report-sha256 sha256:<exact-file-digest>
```

The complete P03 V1 decoder remains unchanged and closed. The projected variant is accepted only
when `sanitized_projection=true` and `raw_source_or_telemetry_included=false`, every projected
object has exactly its allowlisted fields, and all available semantics validate.

## Frozen projected-report validation

Before rendering, the product must:

1. Reuse P03's bounded regular-file, no-symlink, exact-byte digest boundary.
2. Require the exact projection field sets emitted by the existing sanitizer; unknown, missing,
   duplicate, malformed, or future-version fields fail.
3. Validate artifact, envelope, manifest, plan, stage, result, request, observation, evidence,
   source-receipt, file, selected-byte, and report digests wherever retained.
4. Require artifact and manifest equality across identity, plan summary, every stage, and every
   observation; require the scenario-stage result to equal the retained plan digest.
5. Require the plan summary's bounded intent count, reason codes, status, and runtime-binding shape.
   Because scenario intents were deliberately omitted, do not claim to recompute the plan digest.
6. Reconstruct only the retained deterministic-static observation core and recompute each
   observation digest, source/finding/evidence/threat-class/coverage agreement, ordering,
   detection eligibility, and deterministic source-receipt binding.
7. Re-derive observation count, behavior-detection count, disposition, verdict, and exit code.
   Sample name, expected label, advisory, corpus membership, and hash reputation are never verdict
   inputs.
8. Require `package_source_included=false`, `selected_bytes_included=false`,
   `admission_authority=false`, `observed_clean=false`, and `sync_back_enabled=false`.
9. Accept only deterministic-static projected observations in P04. Any AI or behavioral projection
   requires a later versioned contract and is not guessed here.

Successful output must distinguish a complete report from a sanitized projection. It states that
the exact bytes and retained structure matched, while omitted scenario intents, package source,
selected bytes, and raw telemetry were not reopened or re-resolved. Digest matching remains
integrity, not producer authentication.

## Frozen product artifact

Add one concise tracked Markdown report containing:

- the exact four artifact and sanitized-report digests;
- each production `BLOCK` headline, artifact form, eligible behavior names, safe digest/range
  citations, and material coverage gaps;
- `diagnostic 4/4` and `finalized July experimental baseline 7/11` as separate facts;
- no package names as detection evidence and no raw source, selected bytes, event details, private
  paths, credentials, canaries, or restricted report bytes; and
- an explicit statement that this is not the R06 signed subscore or a new 11-sample result.

## Allowed work

- A runner-owned strict decoder/validator for the already-produced sanitized static projection.
- Minimal CLI routing and output-posture wording while reusing the P02 renderer.
- Focused positive, paired review, mutation, compatibility, and leak tests.
- The compact sanitized P04 product report plus README and living status updates.

## Forbidden work

- No raw artifact access, fresh static inspection, hosted AI, VM, cloud/SSH, restricted execution,
  live C2, second-stage fetch, sync-back, or evidence regeneration.
- No detector, rule, scorer, signer, publisher, prompt, sensor, runtime, protocol, backend, or
  general report-schema redesign.
- No P05 reconciliation input or dynamic-evidence presentation.
- No committed restricted projection bytes or private evidence paths.

## Frozen acceptance criteria

1. Exactly four unique artifact/report-digest pairs pass the projection validator and render the
   exact static `BLOCK` headline with exit 20.
2. Each Telnyx report names `download execute capability` from an eligible deterministic-static
   observation with a safe hash/range citation.
3. The npm report names its eligible sensitive-path, exfiltration, and environment-to-process
   capabilities from typed observations.
4. Identity/reputation-only controls cannot create `BLOCK`; projected review and malformed inputs
   remain `REVIEW`/22 or `ERROR`/64 as appropriate.
5. Coverage gaps, omitted-field limits, exact report digest, artifact access none, and no
   installation/admission/sync-back authority are explicit.
6. The tracked compact report says diagnostic 4/4 and finalized July experimental baseline 7/11,
   without claiming R06, 11/11, clean, release, or broad detection coverage.
7. Unknown/missing/duplicate fields; digest, identity, source-receipt, stage, observation,
   eligibility, count, verdict, and authority mutations fail with exit 64 and no `BLOCK` or
   `ALLOW`.
8. Existing complete P03 reports and legacy exact-artifact commands remain compatible.
9. No raw/restricted artifact, projection bytes, secret, cache, or private lab path enters git.
10. The branch is pushed and the standard handoff is completed; P05 is not started.

## Required checks

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-runner retained_report
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli report_render
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli exact_artifact
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-runner --test exact_artifact_spine_v1
python3 scripts/whoathere-development-fixture-baseline-selftest.py
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
```

Also run the built binary against the four frozen local projections, checking exact headlines,
behaviors, report digests, exits, and one recomputed-digest structural mutation. Do not copy those
input bytes into the repository.

## Stop and parking rule

- At 60 minutes, render the first frozen projection or report the exact validator blocker.
- If none renders by 90 minutes, push the bounded reproduction and stop P04.
- Two materially different failed approaches end the chunk.
- At three hours, push safe partial work, record the smallest resume experiment, and return control.

## Required handoff

```text
Chunk: P04
Start SHA / end SHA:
Active time used:
User-visible outcome:
Four artifact/report digest pairs:
Four production results/exits:
Derived behaviors and citations:
Projection limits and compatibility:
Diagnostic score / finalized baseline:
Acceptance criteria passed/not passed:
Safety invariants or not-applicable rationale:
One parked blocker:
Recommendation for P05:
```

## Completion result

```text
Chunk: P04
Start SHA / end SHA: 8d917a7 / pushed P04 branch tip
Active time used: about 40 minutes of tracked active execution; within the hard timebox
User-visible outcome: four source-free prior-miss reports render the exact static BLOCK headline
  through whoathere report render, with current-policy behaviors, citations, gaps, and no authority
Four artifact/report digest pairs: 7321caa3...b8d9 / b6622692...f43; cd081158...5fe3 /
  11770b7f...fd8; a9235c0e...33a5 / 3c784119...01c; 0b8e586c...8933 / bc09a308...e452
Four production results/exits: BLOCK / 20 for all four exact digest pairs
Derived behaviors and citations: all three Telnyx forms name download-execute plus
  environment-to-process capability; npm names two environment-to-process, one
  sensitive-file-exfiltration, and two sensitive-path findings; every displayed group carries a
  retained evidence/file/range digest citation
Projection limits and compatibility: package source, selected bytes, scenario intents, and raw
  telemetry remain omitted and were not reopened; complete P03 reports and exact-artifact commands
  remain compatible; digest matching is integrity, not producer authentication
Diagnostic score / finalized baseline: diagnostic 4/4; finalized July experimental baseline 7/11
Acceptance criteria passed/not passed: 10/10 passed; independent Ultra verification returned GO
  after its coherent eligibility-downgrade exploit was fixed and rerun successfully
Safety invariants or not-applicable rationale: no raw artifact access, package execution, hosted AI,
  VM, cloud/SSH, live C2, second-stage fetch, sync-back, or restricted evidence regeneration;
  rendering grants no clean, installation, admission, release, or publication authority
One parked blocker: none for P04; paired dynamic/Codex presentation remains intentionally deferred
  to P05's separately frozen reconciliation boundary
Recommendation for P05: freeze the exact paired npm inputs and add only their validated
  reconciliation/presentation path; do not reinterpret raw telemetry or build another scorer
```

The production binary rendered all four frozen sanitized projections with exact digest checks and
behavior-derived exit 20 results. A recomputed-digest authority flip and an independently designed,
coherent eligibility downgrade both failed with `ERROR` / 64 and no `BLOCK` or `ALLOW`. The compact
product report preserves diagnostic 4/4 separately from the finalized 7/11 baseline.
