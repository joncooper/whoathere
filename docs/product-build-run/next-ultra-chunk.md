# Next Ultra Chunk: P03 Validated Saved-Report Rendering

Status: complete. P04 remains queued and was not started.

Parent plan: [Detection Reset Ultra Work Chunks](detection-reset-ultra-work-chunks.md)

## Immutable execution contract

```text
Model: GPT-5.6 Codex
Reasoning effort: Ultra
Start commit: ebbd64d
Branch: codex/p03-sanitized-report-render
Timebox: 2-4 active hours; hard stop at 4 hours
Primary metric: one production command renders a digest-matched, structurally valid saved V1
                report without artifact access and rejects every malformed or mismatched control
Forest checks: 60 minutes and after two failed approaches
End rule: push accepted work or a clearly marked WIP reproduction; do not begin P04
```

## User-facing outcome

A user can save an exact-artifact JSON report and later render the same concise P02 `BLOCK` or
`REVIEW` explanation without retaining or reopening the package artifact.

## Frozen command and digest contract

```text
whoathere report render <inspection.json> --report-sha256 sha256:<64 lowercase hex digits>
```

- `--report-sha256` is mandatory and binds the exact saved file bytes, including whitespace.
- Pretty and compact JSON are both accepted when the supplied digest matches those exact bytes.
- The command accepts only `whoathere.exact_artifact_inspection.v1`.
- V1 is a closed schema: unknown fields and unknown enum values are rejected. A future schema gets
  an explicit parser rather than being guessed through V1.
- Input is a bounded regular report file of at most 64 MiB. It is data, never a source of paths to
  open, commands to run, or authority to grant.
- A validated positive returns exit 20; a validated inconclusive or unsupported report returns
  exit 22. Request, read, parse, digest, or semantic validation failure returns exit 64.
- Failure output begins with `ERROR`, contains neither `BLOCK` nor `ALLOW`, and does not echo the
  report path or untrusted input.

The detached digest proves exact-byte matching against a caller-supplied expectation. It is not a
signature, attestation, or proof of producer authenticity, and the product must not describe it as
one.

## Frozen structural validation

Before P02 rendering is called, the retained-report parser must validate:

1. Exact schema version and closed-field decoding.
2. Artifact, envelope, manifest, report, request, result, intent, plan, observation, evidence,
   finding, bundle, event, and selected-byte digests wherever their fields are present.
3. Artifact and manifest identity equality across the identity, every stage, scenario plan,
   scenario intent, and observation.
4. Scenario-intent and scenario-plan digest recomputation plus coherent runtime-binding state.
5. Observation digest recomputation, typed source/finding/evidence agreement, threat-class
   agreement, coverage/gap agreement, event ordering, and artifact binding.
6. Ordered unique observations and reason codes, bounded collection sizes, and valid reason-code
   syntax.
7. Stage names, order, statuses, bindings, reason codes, provider syntax, observation counts, and
   scenario-plan result binding.
8. Verdict, disposition, exit code, and behavior-detection count re-derived from eligible typed
   observations and unsupported status rather than trusted as free-form producer claims.
9. `admission_authority=false`, `observed_clean=false`, and `sync_back_enabled=false`.

The renderer remains allowlist-based. Validation never causes a report to become clean, admitted,
installed, executed, or eligible for sync-back.

## Frozen representative inputs

1. A production-generated synthetic npm static-positive report, saved after exact inspection.
   Delete the synthetic artifact before rendering. Expected: static `BLOCK`, exit 20.
2. A production-generated inert npm review report paired to the same command path. Delete the
   artifact before rendering. Expected: `REVIEW`, exit 22.
3. Mutations of those saved reports covering wrong detached digest, malformed and truncated JSON,
   unknown top-level and nested fields, unknown version, artifact/manifest cross-binding mismatch,
   intent/plan/observation digest mismatch, stage mismatch, verdict/exit/count mismatch, and an
   attempted authority flip. Expected: error exit 64, never `BLOCK` or `ALLOW`.

## Allowed work

- Strict V1 deserialization and retained-report validation in `whoathere-runner`.
- CLI parsing, bounded report-file loading, safe human errors, P02 renderer reuse, and focused
  runner/CLI tests.
- Minimal README usage and updates to this living brief and parent status board.

## Forbidden work

- No new report schema, reconciliation input, signature system, signer, scorer, detector, prompt,
  sensor, runtime, protocol, VM, or backend work.
- No P04 four-miss rendering or tuning.
- No hosted AI, VM, cloud Mac, restricted malware, live C2, second-stage fetch, or sync-back.
- No tracked sample report, public-control artifact bytes, checkpoint document, or broad refactor.

## Frozen acceptance criteria

1. `whoathere report render` accepts a digest-matched structurally valid saved V1 report and reuses
   the P02 renderer.
2. The production synthetic positive renders the exact static `BLOCK` headline and exits 20 after
   its artifact has been deleted.
3. The paired inert report renders the exact `REVIEW` headline and exits 22 after its artifact has
   been deleted.
4. The validated report SHA-256 is visible in successful output.
5. Every malformed, truncated, unknown-field/version, digest, binding, stage, observation, verdict,
   count, or authority mutation fails with exit 64 and cannot render `BLOCK` or `ALLOW`.
6. A path sentinel embedded in every non-rendered identity/provider/reason field is never opened or
   printed; no raw source, selected bytes, event detail, canary, secret, auth path, or private host
   path is rendered.
7. Existing `whoathere inspect`, `whoathere inspect --json`, and legacy `whoathere artifact inspect`
   behavior remains compatible.
8. The command states that it has no admission, installation, artifact-access, or sync-back
   authority and does not call inspection, AI, detonation, or artifact-loading code.
9. No raw/restricted artifact, saved public-control bytes, secret, cache, or private lab data enters
   git.
10. The branch is pushed and the standard handoff is completed; P04 is not started.

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

Also run the built binary against fresh saved synthetic positive and review reports, delete both
artifacts first, and check the real process exits plus one digest-mismatch control.

## Stop and parking rule

- At 60 minutes, render the first saved report without its artifact and name the criteria moved.
- If no saved report renders by 90 minutes, stop and report the exact blocker.
- Two materially different failed approaches end the chunk.
- At four hours, push safe partial work, record the reproduction and smallest resume experiment,
  and return control to the user.

## Required handoff

```text
Chunk: P03
Start SHA / end SHA:
Active time used:
User-visible command:
Positive saved-report result/exit:
Review saved-report result/exit:
Artifact-free proof:
Digest/structural rejection controls:
Compatibility and leak controls:
Acceptance criteria passed/not passed:
Safety invariants or not-applicable rationale:
One parked blocker:
Recommendation for P04:
```

## Completion result

```text
Chunk: P03
Start SHA / end SHA: ebbd64d / pushed P03 branch tip
Active time used: about 35 minutes of tracked active execution; within the hard timebox
User-visible command: whoathere report render <inspection.json> --report-sha256 sha256:<digest>
Positive saved-report result/exit: BLOCK - malicious capability found in package / 20
Review saved-report result/exit: REVIEW - WhoaThere cannot establish that this artifact is safe / 22
Artifact-free proof: both source artifacts and quarantine state were deleted before rendering;
  the command reports and enforces artifact access: none
Digest/structural rejection controls: wrong exact-byte digest, malformed/truncated/duplicate JSON,
  closed-schema/version, cross-binding, intent/plan/observation/evidence/stage, verdict/count/exit,
  and authority mutations all rejected with ERROR / 64 and no BLOCK or ALLOW
Compatibility and leak controls: full runner and 249-test CLI suites passed; raw source, selected
  bytes, event detail, provider/reason sentinels, secrets, canaries, and private paths stayed hidden
Acceptance criteria passed/not passed: 10/10 passed; independent Ultra verification returned GO
Safety invariants or not-applicable rationale: no artifact execution, hosted AI, VM, cloud,
  restricted malware, sync-back, or P04 work; rendering grants no admission authority
One parked blocker: none for P03; detached digest custody is intentionally not producer authentication
Recommendation for P04: freeze it as a separate goal and consume only trusted-custody sanitized reports
```

The production binary rendered artifact-deleted static-positive and inert saved reports with the
frozen headlines and exits. Recomputed-digest stage and request forgeries, a forged behavioral
finding digest, and a detached-digest mismatch all failed closed. The accepted P01 detection
baseline remains unchanged: this chunk made evidence repeatable and usable without claiming a new
malware detection result.
