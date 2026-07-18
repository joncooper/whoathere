# Next Ultra Chunk: P01 Truthful, Panic-Free Baseline

Status: ready, not started

Parent plan: [Detection Reset Ultra Work Chunks](detection-reset-ultra-work-chunks.md)

## Immutable execution contract

```text
Model: GPT-5.6 Codex
Reasoning effort: Ultra
Start commit: 7e6b8d0 plus the accepted planning-only commit
Branch: codex/p01-truthful-baseline
Timebox: 1-2 active hours; hard stop at 2 hours
Primary metric: exact-artifact baseline rows completed without panic or hidden metric mismatch
Forest checks: 60 minutes and after two failed approaches
End rule: push accepted work or a clearly marked WIP reproduction; do not begin P02
```

## User-facing outcome

A developer can run a repeatable baseline over representative npm, wheel, and sdist artifacts and
receive an honest report that does not panic, hide an active detection miss, or falsely accuse the
existing benign controls.

## Known starting result

- The clean base currently detects **0/3** canonical active fixtures through this static product
  path. P01 must report that honestly; it must not manufacture 3/3.
- The paired canonical benign fixtures currently have **0/3** false-malicious results.
- The development-baseline runner currently exits zero when its safety checks pass even if its
  reported detection metric misses. P01 fixes that frozen-metric contract.
- The five existing public benign controls are:
  - `telnyx-4.87.0-py3-none-any.whl`;
  - `telnyx-4.87.0.tar.gz`;
  - `telnyx-4.88.1-py3-none-any.whl`;
  - `telnyx-4.88.1.tar.gz`; and
  - `sbx-2.1.0.tgz`.

## Allowed work

- Build `whoathere artifact inspect` from the clean product base.
- Run the six paired canonical active/benign fixtures.
- Freeze the five public controls by coordinate, form, and exact hash in a tracked manifest. Do not
  track their bytes.
- Inspect those five controls if the existing local benign copies are present.
- Add one small tracked synthetic archive fixture containing an em dash and curly apostrophe.
- Make the development-baseline runner fail when a frozen expected metric mismatches.
- Add only focused tests for the metric gate and Unicode-safe production parsing.

## Forbidden work

- Do not cherry-pick or repair WIP commits `86e0cce` or `0b2a7ae`.
- Do not add or tune a detector, AI prompt, VM sensor, protocol, schema, scorer, signer, runtime, or
  backend.
- Do not redesign human output; that is P02.
- Do not access, unpack, inspect, or execute restricted malware.
- Do not start a VM, use the cloud Mac, or perform hosted AI review.
- Do not create another checkpoint document.

## Frozen acceptance criteria

1. No inspected input panics.
2. The three canonical active fixtures are reported honestly as 0/3 behavior-positive and
   conservative `REVIEW`/exit 22.
3. The three paired canonical benign fixtures have zero false-malicious results.
4. All five exact public benign controls are present, frozen by hash, inspected once, and have zero
   false-malicious results. An unavailable control blocks P01 rather than becoming a pass; do not
   turn acquisition into a new workstream inside this chunk.
5. No incomplete/no-positive result becomes exit 0, clean, allow, admission, or sync-back eligible.
6. The synthetic Unicode archive exercises the production parser in an automated test.
7. A self-test that deliberately changes an expected metric makes the baseline runner exit
   nonzero.
8. The tracked manifest rejects duplicate IDs, unsupported forms, malformed hashes, and changed
   artifact bytes.
9. No raw/restricted artifact, secret, canary, generated cache, or private lab configuration enters
   git.
10. The branch is pushed and the standard handoff is completed.

## Required checks

```sh
cargo build --manifest-path whoathere/Cargo.toml -p whoathere-cli
cargo test --manifest-path whoathere/Cargo.toml \
  -p whoathere-detector --test artifact_bound_analysis
cargo test --manifest-path whoathere/Cargo.toml \
  -p whoathere-runner --test exact_artifact_spine_v1
cargo test --manifest-path whoathere/Cargo.toml \
  -p whoathere-cli exact_artifact
python3 scripts/whoathere-development-fixture-baseline-selftest.py
python3 scripts/whoathere-development-fixture-baseline.py \
  --whoathere-bin "$PWD/whoathere/target/debug/whoathere" \
  --output-dir /tmp/whoathere-development-baseline
```

If a test name or path has changed, make the minimum mechanical correction needed to run the
existing check. Do not turn test discovery into a refactor.

## Stop and parking rule

- At 60 minutes, report which artifacts ran and which frozen criteria moved.
- If no representative artifact row exists by 90 minutes, stop implementation and report why.
- Two materially different failed approaches end the chunk.
- At two hours, push safe partial work, record the exact reproduction and smallest next experiment,
  and return control to the user.

## Required handoff

```text
Chunk: P01
Start SHA / end SHA:
Active time used:
Canonical active detections:
Canonical benign false-malicious:
Public benign rows present/missing:
Public benign false-malicious:
Panics:
Metric mismatch test:
Acceptance criteria passed:
Acceptance criteria not passed:
Safety invariants or not-applicable rationale:
One parked blocker:
Recommendation for P02:
```
