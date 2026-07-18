# Next Ultra Chunk: P02 Human `whoathere inspect`

Status: complete. P03 remains queued and was not started.

Parent plan: [Detection Reset Ultra Work Chunks](detection-reset-ultra-work-chunks.md)

## Immutable execution contract

```text
Model: GPT-5.6 Codex
Reasoning effort: Ultra
Start commit: f4c07e5
Branch: codex/p02-human-inspect
Timebox: 2-4 active hours; hard stop at 4 hours
Primary metric: one production human command renders the frozen BLOCK and REVIEW outcomes while
                preserving the exact JSON contract and exit codes
Forest checks: 60 minutes and after two failed approaches
End rule: push accepted work or a clearly marked WIP reproduction; do not begin P03
```

## User-facing outcome

A developer can run `whoathere inspect <artifact>` and receive concise, actionable text explaining
why an exact npm, wheel, or sdist artifact is blocked or needs review. Automation can add `--json`
to receive the existing exact-artifact JSON contract.

## Frozen command contract

- `whoathere inspect <artifact>` produces human text.
- `whoathere inspect <artifact> --json` produces the existing JSON report byte-for-byte.
- Existing `whoathere artifact inspect <artifact>` remains JSON-by-default and backward compatible.
- The typed report or typed error supplies the process exit code before either renderer runs.
- Human output never contains `ALLOW`; this command has no installation or sync-back authority.

Frozen headlines:

```text
BLOCK - malicious capability found in package
BLOCK - malicious behavior observed in disposable VM
REVIEW - WhoaThere cannot establish that this artifact is safe
```

When both eligible modalities are present, name both. An eligible behavioral observation may use
the disposable-VM wording only when the report also binds a successful known Linux-VZ detonation
provider. Otherwise expose the missing VM binding without inventing it.

## Frozen representative inputs

1. A synthetic npm capability archive shaped like the existing `npm_capability_tgz` test fixture,
   with a typed deterministic `credential_exfiltration_capability` observation. It is parsed but
   never executed. Expected result: static `BLOCK`, exit 20.
2. A locally constructed typed report with an eligible behavioral observation and a known
   Linux-VZ detonation-stage binding. No VM or AI runs. Expected rendering: VM `BLOCK`, exit 20.
3. The P01 canonical benign npm, wheel, and sdist fixtures. Expected result for each:
   conservative `REVIEW`, exit 22, never clean or allow.

## Human output contract

Render only allowlisted typed fields:

- declared package name and version when present;
- ecosystem, artifact format, byte length, and artifact SHA-256;
- evidence modality, typed behavior, threat class, confidence, and safe hash/range citation;
- material observation, scenario, and non-complete-stage coverage gaps;
- a clear next action and explicit lack of installation/sync-back authority.

Do not render artifact/state/auth paths, source coordinates, CAS keys, provider-private paths, raw
source, selected bytes, event detail, canary values, secrets, credentials, or whole debug objects.
Reason strings, package identity, advisories, lifecycle events, ordinary network sends, and
sinkhole telemetry cannot independently create a `BLOCK` headline.

## Allowed work

- CLI parsing, help, typed exact-inspection evaluation, human rendering, and focused CLI tests.
- Minimal test-only construction of typed static, VM-bound behavioral, and review reports.
- Updates to this living brief and the parent status board.

## Forbidden work

- No report/evidence schema, deserialization, reconciliation, scorer, signer, detector, prompt,
  sensor, runtime, protocol, backend, or VM changes.
- No P03 retained-report rendering boundary.
- No hosted AI, VM, cloud Mac, restricted malware, live C2, second-stage fetch, or sync-back.
- No new checkpoint document and no broad CLI refactor.

## Frozen acceptance criteria

1. `whoathere inspect` is a human-default alias over the production exact-artifact path.
2. Static-positive text contains the exact static `BLOCK` headline, typed behavior, confidence,
   safe citation, coverage, identity, and no-authority statement; exit is 20.
3. A typed, Linux-VZ-bound behavioral positive contains the exact VM `BLOCK` headline and safe
   event-digest citations; exit is 20.
4. No-positive/incomplete npm, wheel, and sdist reports contain the exact `REVIEW` headline,
   material gaps, a manual-review action, and no `ALLOW`; exit is 22.
5. Text and JSON modes use the same pre-render exit code.
6. `whoathere inspect --json` is byte-for-byte equal to legacy `whoathere artifact inspect` JSON
   for the same fixed input and acquisition time.
7. Existing exact-artifact JSON/error behavior and P01 baseline remain compatible.
8. Leak-sentinel tests prove the human renderer omits raw source, selected bytes, canary/secret
   values, auth/private paths, and untrusted event detail.
9. No raw/restricted artifact, public-control bytes, secret, cache, or private lab data enters git.
10. The branch is pushed and the standard handoff is completed; P03 is not started.

## Required checks

```sh
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-cli exact_artifact
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-runner --test exact_artifact_spine_v1
python3 scripts/whoathere-development-fixture-baseline-selftest.py
python3 scripts/whoathere-development-fixture-baseline.py \
  --whoathere-bin "$PWD/whoathere/target/debug/whoathere" \
  --output-dir <fresh-temp-directory>
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
```

Also run the built binary against the frozen synthetic static-positive artifact and the canonical
benign npm, wheel, and sdist controls, checking stdout and the real process exit status.

## Stop and parking rule

- At 60 minutes, show the first human artifact result and name the criteria moved.
- If no human artifact result exists by 90 minutes, stop and report the exact blocker.
- Two materially different failed approaches end the chunk.
- At four hours, push safe partial work, record the reproduction and smallest next experiment,
  and return control to the user.

## Required handoff

```text
Chunk: P02
Start SHA / end SHA:
Active time used:
User-visible command:
Static-positive result/exit:
VM-positive renderer result/exit:
Review controls/result/exit:
JSON parity and legacy compatibility:
Leak controls:
Acceptance criteria passed/not passed:
Safety invariants or not-applicable rationale:
One parked blocker:
Recommendation for P03:
```

## Completion result

```text
Chunk: P02
Start SHA / end SHA: f4c07e5 / pushed P02 branch tip
Active time used: within the 2-4 hour budget
User-visible command: whoathere inspect <artifact> [--json]
Static-positive result/exit: BLOCK - malicious capability found in package / 20
VM-positive renderer result/exit: BLOCK - malicious behavior observed in disposable VM / 20
Review controls/result/exit: canonical npm, wheel, and sdist / REVIEW / 22
JSON parity and legacy compatibility: byte-for-byte parity proved; legacy JSON remains the default
Leak controls: source, selected bytes, canary values, untrusted detail, and private paths omitted
Acceptance criteria passed/not passed: 10/10 passed
Safety invariants or not-applicable rationale: no package execution, VM, AI, cloud, or malware use;
  the command grants no installation or sync-back authority
One parked blocker: none; independent Ultra review returned GO after human typed-error repair
Recommendation for P03: begin only as a separately frozen goal
```

Verification completed with the production binary and representative exact artifacts. The static
synthetic control returned the frozen BLOCK headline and exit 20. Canonical npm, wheel, and sdist
controls each returned the frozen REVIEW headline and exit 22. The five-control P01 public benign
baseline retained zero false-malicious results, and the accepted P01 detection baseline remains
unchanged rather than being inflated by presentation work.
