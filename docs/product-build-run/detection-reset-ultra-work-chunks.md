# WhoaThere Detection Reset: Ultra Work Chunks

Date: 2026-07-18

Status: active near-term execution plan

Current runnable scope: [Next Ultra Chunk](next-ultra-chunk.md)

This document controls product work after the July 9-18 retrospective. The larger
[artifact-native plan](artifact-native-detection-execution-plan.md) remains an architecture and
research reference; it is not an instruction to resume every unfinished subsystem.

## 1. One-sentence goal

Give a developer one command that inspects an exact npm or PyPI artifact away from the host and
returns an evidence-cited `BLOCK` or conservative `REVIEW`, then qualify one frozen build against
the eleven-sample regression corpus and a forty-artifact development benign cohort.

## 2. Starting state and branch policy

The clean product base is commit `7e6b8d0` (`Complete paired npm behavior handoff`).

- Clean planning branch: `codex/product-detection-slices-2026-07-18`.
- WIP safekeeping branch: `codex/detection-reset-2026-07-18`.
- WIP commit `86e0cce` preserves the verified-evidence registry prototype.
- WIP commit `0b2a7ae` preserves the sensitive-HTTPS static-rule experiment.
- Neither WIP commit is part of the product baseline or an implied merge candidate.

The WIP static rule did not match the exact malicious npm artifact, its registry self-test fails
manifest validation, and it can panic on ordinary UTF-8 punctuation in public benign artifacts.
It remains research custody only.

Each chunk starts from the last accepted product commit on a branch named
`codex/<chunk-id>-short-outcome`. A failed chunk does not become the next base.

## 3. Honest baseline

| Measure | July 18 baseline |
| --- | --- |
| Finalized July experimental known-corpus baseline | 7/11 |
| Previous misses with useful behavior-specific diagnostic evidence | 4/4 |
| Previous misses in one validated detection subscore | 0/4 |
| Human-readable exact-artifact command | Not available |
| Canonical static active fixtures detected | 0/3 |
| Canonical paired benign false-malicious results | 0/3 |
| Development benign cohort frozen/measured | 0/40 |
| Exact forms with exercised physical paths | 3/3 |

The existing development-baseline runner reports the active 0/3 result but currently exits zero
because it gates safety rather than the frozen detection metric. P01 corrects that measurement
contract; it does not pretend the clean base already detects those fixtures.

The three Telnyx misses have behavior-specific exact static evidence. The missed npm artifact has
behavior-specific static findings and paired disposable-VM/Codex diagnostics. The immediate gap is
product presentation and repeatable orchestration, not another general detector.

### 3.1 Why this reset exists

The July 9-18 task spanned about 199.5 wall-clock hours and accumulated about 113 hours 50 minutes
of goal-active tracker time, roughly 255 commits, and 159 checkpoint documents while the finalized
experimental result remained 7/11. Tracker-active time includes automatic continuations and waits,
so it is not human hands-on time. It still shows the execution failure: high activity did not
reliably change the product scoreboard.

The root error was making release-grade telemetry completeness, signing, and evaluator machinery
prerequisites for a useful malicious-package block. This plan keeps those trust properties where
they are actually needed while refusing to place them ahead of a product-visible result.

## 4. Product and evaluation semantics

Keep these four questions independent:

1. **Product action:** `BLOCK` or `REVIEW`.
2. **Behavior-positive detection subscore:** did valid general evidence detect the malicious
   artifact?
3. **Safety:** did host execution, sync-back, unsafe admission, restricted-material leakage, live
   C2, live second-stage fetch, or invalid teardown occur?
4. **Completion/quality:** is evidence complete enough for the frozen evaluation gate or clean
   admission?

A structurally valid malicious positive may produce `BLOCK` even when sibling coverage is
incomplete. Incomplete coverage can never produce clean, allow, admission, or sync-back.

Human wording preserves modality:

- Static evidence: `BLOCK - malicious capability found in package`.
- VM evidence: `BLOCK - malicious behavior observed in disposable VM`.
- Both: name both capability and observed behavior.
- No positive or unsupported/incomplete work: `REVIEW - WhoaThere cannot establish that this
  artifact is safe`.

Sinkhole connects/sends and package-forgeable markers are supporting telemetry unless an
independent verifier proves an allowlisted behavior-specific evidence type. They are not silently
relabeled as credential exfiltration.

## 5. Non-negotiable chunk controls

### 5.1 Execution envelope

- One fresh Codex task, GPT-5.6 Codex at **Ultra**, for one chunk only.
- Target 1-4 active hours. The stated chunk limit is a hard stop.
- Do not automatically begin the next chunk.
- At most two bounded subagents: one audit and one independent verification pass. No nested trees.
- Freeze the user outcome, inputs, expected result, and tests before code changes.
- One primary metric and one blocker per chunk.
- If no package result, user-visible report, cohort row, or score changes within 90 minutes, stop
  and reassess.
- Two materially different failed approaches end the chunk. A third requires a new chunk and user
  approval.
- Prefer one implementation commit plus one small outcome/documentation commit.
- Push before reporting completion or blockage.

### 5.2 Forest checks

At 60 minutes, after two failed attempts, and before any new protocol, schema, sensor, verifier,
runtime, or backend work, answer:

1. Can a user do something valuable now that they could not do at chunk start?
2. Which frozen criterion or scoreboard number moved?
3. Is the blocker demonstrated by the representative input, or only anticipated?
4. What is the smallest remaining change that fits the timebox?

At the hard stop, push safe partial work as WIP, record the exact reproduction and smallest resume
experiment, and return control to the user.

### 5.3 Forbidden scope unless the current input proves it necessary

- New general VM sensors, telemetry protocols, signing hierarchies, or taint engines.
- IPv6, GSO, TLS interception, live C2, or live second-stage fetching.
- General refactors, new backends, GUI, installer, enterprise proxy, Cloudflare, Firecracker, or
  AWS work.
- Mutation, held-out, or 120-artifact qualification before this plan completes.
- Work whose only user-visible result is more internal tests, schemas, receipts, or documentation.

### 5.4 Restricted-material controls

- Raw malware remains on the approved cloud Mac.
- Never execute, unpack, or inspect raw malware on the local Mac.
- Never use Docker for detonation.
- Never sync back, contact live C2, fetch a live second stage, or use real credentials.
- Do not commit raw artifacts, archives, VM disks, packet captures, canary values, credentials,
  host-private configuration, or unsanitized telemetry.
- Every restricted access/run requires a fresh explicit user authorization and a current green lab
  preflight that records provider/legal posture, cloud and host default deny, LuLu, sinkhole,
  custody, clearance, evidence storage, sanitization, and stale-state checks.
- Hosted review of restricted source requires separate approval. Sanitized verified behavior may
  use the separately approved observe-only Codex path.

### 5.5 Canonical safety invariants

Every execution chunk reports each field as `zero` or `unknown`, with its receipt/run reference:

- host package execution;
- sync-back;
- unsafe allow or admission;
- restricted-material leak;
- live-C2 contact;
- live second-stage fetch; and
- invalid or unverified teardown.

`Unknown` fails completion. “Safety passed” without individual values is insufficient.

### 5.6 Documentation discipline

This is the single strategy/status document. `next-ultra-chunk.md` is the single runnable brief.
Update them rather than creating a dated checkpoint for every internal change. Release/evaluation
reports are allowed because they are user-facing product artifacts.

## 6. Completion contracts

Different chunk types have different definitions of done.

### Implementation chunk

- The named user command/output works through the production code path.
- The changed behavior and one paired negative/benign control pass.
- Malformed or mismatched input remains conservative.
- The branch is pushed and the scoreboard is updated.

### Measurement chunk

- Inputs and expected denominator were frozen before results.
- No code, prompt, policy, runtime, or scoring change occurs during the batch.
- Every selected input has a visible final row, including failures.
- Results are reported honestly; misses are not repaired inside the measurement chunk.

### Preflight chunk

- Outcome is either `ready` with all required identities/controls, or `blocked` with one exact
  operator action.
- No artifact access or VM start occurs.

### Publication chunk

- Exact denominator, identities, detection, completion/quality, safety, and overall pass status are
  shown independently.
- Missing, duplicate, unknown, signature, manifest, projection, and identity tampering fails.
- Incomplete coverage is visible and cannot imply release, clean, or admission readiness.

### Blocked handoff

- Safe partial work is pushed as WIP.
- The exact reproduction, attempts made, evidence learned, and smallest resume experiment are
  recorded.
- No next chunk begins automatically.

## 7. Standard handoff

```text
Chunk:
Start SHA / end SHA:
Active time used:
User-visible outcome:
Command or report:
Representative input(s):
Paired control(s):
Acceptance criteria passed:
Acceptance criteria not passed:
Diagnostic detection score:
Claim-bearing detection subscore:
Completion/quality gate:
Overall evaluation passed:
Safety invariants (each zero/unknown plus receipt reference):
One parked blocker:
Recommended next chunk:
```

Commit count, lines changed, subagent count, checkpoint count, and unit-test count are not product
metrics.

## 8. Status board

Only the first `ready` row is authorized. Templates are instantiated as unique chunks only after
their exact inputs and criteria are frozen.

| ID | User-visible outcome | Budget | Status | Primary gate |
| --- | --- | ---: | --- | --- |
| P00 | Preserve WIP and establish the reset plan | 1-2h | complete | Recoverability |
| P01 | Establish a truthful, panic-free exact-artifact baseline | 1-2h | complete | Reliability/measurement |
| P02 | Add human `whoathere inspect` output | 2-4h | complete | Usable product |
| P03 | Add a validated sanitized-report rendering boundary | 2-4h | complete | Repeatable product evidence |
| P04 | Render four previous misses as product reports | 1-3h | complete | Diagnostic 4/4 |
| P05 | Add paired npm VM/Codex evidence to its report | 2-4h | complete | AI/dynamic value |
| P06 | Add cloud-lab ready/not-ready preflight | 1-2h | complete | Operability/safety |
| P07 | Run one-command inert static/VM/Codex demo | 2-4h | complete | Fresh final-code physical invocation |
| R01 | Freeze a positive-only four-miss subscore contract | 2-4h | complete | Evaluation contract |
| R02 | Prove the subscore path with synthetic 4/4 | 2-4h | ready | Evaluator readiness |
| R02b | Freeze final four-miss tool identities and manifest | 1-2h | queued | Evidence-collection identity |
| R03 | Refresh lab preflight for restricted rows | 1-2h | queued | Restricted-lab readiness |
| R04 | Produce three frozen Telnyx static rows | 2-4h | queued | Frozen positives 3/4 |
| R05 | Produce one independently verified npm row | 2-4h | queued | Frozen inputs 4/4 |
| R06 | Publish the 4/4 behavior-positive prior-miss report | 1-3h | queued | Detection subscore 4/4 |
| M01 | Static-measure four npm corpus artifacts | 1-3h | queued | Diagnostic corpus rows |
| M02 | Static-measure four npm corpus artifacts | 1-3h | queued | Diagnostic corpus rows |
| M03 | Static-measure three PyPI corpus artifacts | 1-3h | queued | Diagnostic corpus rows |
| B01 | Freeze the forty-artifact benign cohort | 2-4h | queued | Benign denominator |
| B02 | Measure one benign npm pilot | 1-3h | queued | Batch sizing |
| B03 | Measure one benign wheel pilot | 1-3h | queued | Batch sizing |
| B04 | Measure one benign sdist pilot | 1-3h | queued | Batch sizing |
| Q01 | Freeze the final build and both qualification manifests | 2-4h | queued | Final identity |
| Q02 | Refresh lab preflight for final qualification | 1-2h | queued | Qualification readiness |
| Q03 | Rerun four frozen npm malware rows | 2-4h | queued | Final malware rows |
| Q04 | Rerun four frozen npm malware rows | 2-4h | queued | Final malware rows |
| Q05 | Rerun three frozen PyPI malware rows | 2-4h | queued | Final malware rows |
| Q06 | Publish final malware and benign reports | 1-3h | queued | 11/11 and benign gates |
| A01 | Package and document the local detection alpha | 2-4h | queued | Usable alpha |
| A02 | Complete an inert clean-Mac VM smoke | 2-4h | queued | User reproducibility |

The following are templates, not authorized rows:

- `M-FIX-<sample>`: one residual malware miss, 1-4h.
- `B-BATCH-<nn>`: one measured benign batch of at most five, 2-4h.
- `B-FIX-<family>`: one false-positive/friction family, 1-4h.
- `Q-BENIGN-<nn>`: one final frozen benign batch sized from pilots, 2-4h.

## 9. Product chunks

### P01 - Truthful, panic-free exact-artifact baseline

**User outcome:** Representative npm, wheel, and sdist artifacts can be inspected without panic,
and the baseline command fails when its frozen metrics unexpectedly change.

**Budget:** 1-2 hours.

**Allowed:**

- Build `whoathere artifact inspect` from `7e6b8d0`.
- Run the six canonical active/benign fixtures.
- Freeze the five existing public benign controls by coordinate, form, and exact hash in a tracked
  manifest; do not track their bytes.
- Run those five controls when locally available.
- Add one small synthetic Unicode archive containing an em dash and curly apostrophe.
- Make the development-baseline runner fail on frozen metric mismatch instead of safety alone.

**Forbidden:** WIP rule repair/cherry-pick, new detection, AI, VM, cloud, malware, human-output
redesign, or campaign work.

**Acceptance:**

1. No inspected input panics.
2. The current canonical active result is recorded honestly as 0/3 behavior-positive and `REVIEW`.
3. The three paired benign fixtures and all five exact-hash public benign controls have zero
   false-malicious results. A missing public control blocks P01 rather than becoming a pass; do not
   turn acquisition into a new workstream inside this chunk.
4. Incomplete/no-positive results remain exit 22; never exit 0, clean, allow, or admission.
5. The Unicode fixture exercises the production parser.
6. Deliberately changing an expected baseline metric makes the runner exit nonzero.
7. No raw/restricted artifact, secret, cache, or private lab data enters git.

### P02 - Human `whoathere inspect`

**User outcome:** A developer runs `whoathere inspect <artifact>` and receives actionable text;
`--json` preserves the existing report contract.

**Budget:** 2-4 hours.

**Acceptance:**

1. Exit 20/22 is derived before rendering and remains identical in text and JSON modes.
2. A typed static-positive report renders `BLOCK - malicious capability found in package`.
3. A typed VM-positive report renders `BLOCK - malicious behavior observed in disposable VM`.
4. A no-positive/incomplete report renders `REVIEW` and never `ALLOW`.
5. Output names artifact identity, evidence modality, behavior, confidence, citations, material
   coverage gaps, and lack of installation authority.
6. Output leaks no source, selected bytes, canary, secret, auth path, or private host path.
7. Existing `whoathere artifact inspect` remains backward compatible.

If a display fact is absent, expose the gap; do not redesign evidence schemas.

### P03 - Validated sanitized-report rendering boundary

**User outcome:** A user can render a previously produced sanitized inspection report without raw
artifact access, and malformed or mismatched reports are rejected.

**Budget:** 2-4 hours.

**Target:** A versioned command such as `whoathere report render <inspection.json>`, reusing P02's
renderer. A validated optional reconciliation input is deferred to P05.

**Acceptance:**

1. Version, artifact identity, report digest, stage status, observations, citations, coverage, and
   verdict are structurally validated before rendering.
2. Unknown fields follow the frozen compatibility policy; malformed, truncated, or digest-mismatched
   input fails and cannot render `BLOCK`.
3. A synthetic positive and paired review report exercise the production path.
4. This command has no clean/admission authority and never accesses artifact bytes.

### P04 - Four prior misses as product reports

**User outcome:** Four compact reports show why the four July misses are now blocked.

**Budget:** 1-3 hours.

Use existing sanitized reports through P03. If fresh static inspection is desired, require a green
P06 preflight and explicit restricted-access approval first; do not execute package code.

**Acceptance:**

1. Exactly four unique digest-bound reports render `BLOCK`.
2. Three Telnyx reports name reachable download-and-execute capability.
3. The npm report names its current behavior-specific static capabilities.
4. No sample name, corpus label, advisory, hash reputation, or expected label drives the verdict.
5. Coverage gaps and no installation authority are explicit.
6. A compact sanitized report says diagnostic 4/4 and finalized July experimental baseline 7/11.

### P05 - Paired npm VM/Codex evidence in the product report

**User outcome:** The npm report separately presents static capability and what the disposable VM
and Codex observed under both CI profiles.

**Budget:** 2-4 hours.

Extend P03 with one versioned, validated reconciliation input. Do not reinterpret raw telemetry or
create another scorer.

**Acceptance:**

1. Exact artifact, manifest, profile, evidence, and reconciliation identities match or fail.
2. Both CI profiles display lifecycle execution and credential-file reads.
3. Connect/send intent is described as observed supporting activity, not payload exfiltration.
4. Codex citations resolve to verified event identities.
5. Incomplete coverage remains visible; action remains `BLOCK`.
6. Mismatch, forgery, omission, duplication, and unsupported-version controls fail.

### P06 - Cloud-lab ready/not-ready preflight

**User outcome:** Before any cloud VM or restricted access, the operator receives `ready` or one
exact blocker.

**Budget:** 1-2 hours.

**Acceptance:**

1. Authorization/provider posture, SSH/source route, cloud/host default deny, PF, LuLu, sinkhole,
   VZ, runtime/helper identities, custody, evidence storage, sanitization, clearance, and stale
   process/clone state are checked as applicable to the planned run.
2. No artifact opens and no VM starts.
3. Output binds the intended host, code, runtime, policy, and campaign/profile identities.
4. Outcome is green `ready` or one exact operator action.

One repair attempt is allowed; then park the lab issue and return to local work.

### P07 - One-command inert static/VM/Codex demonstration

**User outcome:** One documented command performs exact artifact -> static analysis -> fresh VM ->
telemetry -> Codex -> human report on a wholly inert package.

**Budget:** 2-4 hours. P06 must be current and green.

**Acceptance:**

1. One user command starts the existing workflow using a finite existing npm detonation profile;
   designing a unified profile subsystem is out of scope.
2. Exact digest continuity holds across every stage.
3. Lifecycle and local-sinkhole activity appears as typed evidence; package-forgeable canary marker
   evidence remains explicitly supporting-only.
4. Codex cites verified events and has no containment/admission authority.
5. All canonical safety invariants are zero with receipt references.
6. Missing coverage remains `REVIEW`; the fixture is never called clean.
7. A sanitized transcript is suitable for the README/portfolio.

## 10. Four-miss detection-subscore chunks

These chunks create a dated positive-only detection subscore. They do not claim complete evidence,
overall evaluation success, clean admission, or a new full-corpus baseline.

### R01 - Freeze the positive-only contract

**User outcome:** An evaluator can read and validate the exact four-row detection-subscore contract
before evidence collection.

**Budget:** 2-4 hours.

Freeze the semantic contract: exact artifacts/forms/profiles, stable expected behavior labels,
permitted positive modalities, incomplete-coverage policy, thresholds, evaluation-window rules,
and required identity fields. R01 does not freeze tool digests that R02 is allowed to change.

The existing complete-run four-miss profile remains unchanged. This is a separate explicitly named
positive-only subscore profile. No evidence is collected in R01.

### R02 - Synthetic 4/4 subscore path

**User outcome:** A synthetic campaign proves how four valid positives can coexist with incomplete
coverage and overall failure.

**Budget:** 2-4 hours.

**Allowed:** Only the positive-only profile, compiler, publisher/bridge, scorer summary, and focused
self-tests needed for this subscore.

**Acceptance:**

- detection subscore 4/4;
- safety passes for the synthetic rows;
- completion/quality fails;
- `overall_passed=false`;
- clean/admission/release false;
- generic safe blocks remain misses; and
- omission, duplication, substitution, signature, profile, projection, and identity tampering fail.

At four hours, park the exact missing bridge. Do not expand into complete clean-admission
verification.

### R02b - Freeze final four-miss identities and manifest

**User outcome:** Evidence collection has one immutable, validated manifest bound to the exact
tools that passed R02.

**Budget:** 1-2 hours.

Freeze and hash the final artifact/profile denominator, evaluation window, verifier key digest,
and code/runtime/sensor/verifier/prompt/model/provider/policy/compiler/publisher/scorer identities.
No R02b-bound tool or policy may change during R03-R06. Any required change invalidates collected
rows and requires a new R02b freeze.

### R03 - Restricted-lab preflight refresh

**User outcome:** A fresh P06 result is bound to the R02b manifest and explicit authorization before
any retained artifact is opened.

**Budget:** 1-2 hours.

### R04 - Three frozen Telnyx static rows

**User outcome:** Three citation-complete frozen positive rows exist without package execution.

**Budget:** 2-4 hours on the approved cloud Mac after R03.

**Acceptance:**

1. Exact hashes and tool identities match R02b.
2. The measured static verifier independently reopens each archive and derives its projection.
3. No package code, VM, hosted AI, or package network activity occurs.
4. A frozen benign archive plus omission, range, digest, signature, and substitution controls pass.
5. Output is three validated staged inputs; the four-row campaign remains incomplete.

### R05 - One independently verified npm row

**User outcome:** The fourth frozen positive row is derived from a fresh approved VM run.

**Budget:** 2-4 hours after a fresh R03-equivalent preflight.

**Acceptance:**

1. Exact artifact, sealed closure, profiles, and identities match R02b.
2. A frozen independent verifier authenticates the ordered denominator for every primitive stream
   used by the positive and derives the claim-bearing observation; producer/Codex labels cannot
   satisfy it.
3. The verifier-derived projection set is compared exhaustively with the published row.
4. Connect/send intent remains supporting unless an allowlisted payload-bearing evidence type is
   independently proved.
5. An inert dependency-shaped control plus missing/forged/duplicated/reordered/substituted receipt
   controls pass.
6. All safety invariants are zero with references.

If that trust boundary cannot be completed within four hours, park it. P01-P07 remain useful and
R06 does not publish 4/4.

### R06 - 4/4 behavior-positive prior-miss report

**User outcome:** A reader receives a sanitized report titled according to the gates it actually
passes.

**Budget:** 1-3 hours.

**Acceptance:**

- exact denominator and identities validate;
- behavior-positive detection subscore is 4/4;
- detection, completion/quality, safety, and overall status are shown independently;
- if coverage is incomplete, title is `4/4 behavior-positive prior misses; incomplete coverage`,
  completion/quality fails, and `overall_passed=false`;
- no clean, admission, release, or full-corpus-baseline claim; and
- tamper controls fail.

## 11. Diagnostic corpus and benign measurement

These phases permit tuning afterward, so their results are diagnostic. They are not the final
qualification reports.

### M01, M02, M03 - Static sweep

- M01: first four frozen npm artifacts, 1-3h.
- M02: remaining four frozen npm artifacts, 1-3h.
- M03: three frozen PyPI artifacts, 1-3h.

Before M01, freeze exact hashes and the current product identity. Each measurement chunk makes no
code/prompt/policy/scorer change, inspects each artifact once on the approved cloud Mac after a
fresh preflight and authorization, exports sanitized reports, and records every `BLOCK`, `REVIEW`,
and infrastructure result. No VM or hosted source review is used during this static sweep.

### M-FIX-<sample> - One residual miss

Instantiate one uniquely named 1-4h chunk per residual artifact. Use the smallest existing path:

1. surface deterministic evidence already present;
2. existing Codex source review with explicit hosted-source approval; or
3. existing VM/Codex behavior path with fresh preflight and approval.

Two approaches or four hours ends the chunk. Never combine misses or build a generic subsystem.

### B01 - Freeze forty benign artifacts

**Budget:** 2-4 hours.

Freeze exact hashes, provenance, selection rationale, expected legitimate triggers,
dependency/build-closure posture, and expected unsupported conditions across explicit npm, wheel,
sdist, clean-neighbor, and legitimate challenge quotas. Independent benign-ground-truth review
occurs before results; detector output cannot influence membership.

### B02, B03, B04 - One per-form pilot

- B02: one npm, 1-3h.
- B03: one wheel, 1-3h.
- B04: one sdist, 1-3h.

Each reaches the intended legitimate trigger where supported, records a final row even if
false-malicious or friction-producing, measures runtime/operator intervention, and changes no code.

### B-BATCH-<nn> - Measured benign batch

Instantiate unique 2-4h chunks from pilot timing, each capped at five artifacts and 150 estimated
minutes. Code does not change during a batch. Classifications are `no behavior-specific positive /
REVIEW`, false-malicious, unsupported, or infrastructure-error unless complete signed evidence
genuinely supports `observed_clean`.

### B-FIX-<family> - One false-positive/friction family

One 1-4h chunk may repair one measured family. Affected benign rows must improve, a paired
malicious/canary fixture must still block, and diagnostic malware results must not decline. Two
attempts, then park.

## 12. Final frozen-build qualification

Do not begin Q01 until:

- the latest release candidate produces a behavior-specific `BLOCK` for every known-regression
  artifact through targeted rechecks; unresolved known misses block Q01, and mixed
  pre-remediation rows are diagnostic only and cannot satisfy final publication;
- all forty development benign rows have been measured;
- selected false-positive/friction remediation is complete; and
- the product command and inert end-to-end demo work.

### Q01 - Freeze final build and manifests

**User outcome:** The exact binary/runtime/prompt/policy/verifier/scorer identity to be released is
frozen together with final eleven-malware and forty-benign denominators.

**Budget:** 2-4 hours.

No product change is permitted after Q01. Any failure requiring code/prompt/policy/runtime change
invalidates all qualification rows, returns to remediation, and requires a new Q01 identity.

### Q02 - Final qualification preflight

Refresh P06 against Q01 with explicit authorization. Budget 1-2h.

### Q03, Q04, Q05 - Final malware rerun

- Q03: four frozen npm rows, 2-4h.
- Q04: four frozen npm rows, 2-4h.
- Q05: three frozen PyPI rows, 2-4h.

No tuning or code changes. Use the minimum frozen evidence path that satisfies each expected
behavior. Every row, including failure, remains visible. A miss fails the target gate but remains a
publishable failed row; it is not fixed inside Q03-Q05.

### Q-BENIGN-<nn> - Final benign rerun

Before Q01, instantiate uniquely named batches sized from B02-B04 timing. Rerun all forty exact
artifacts under the Q01 identity with no code changes. No pre-remediation result may be reused as a
current false-positive/friction rate.

### Q06 - Publish final reports

**Budget:** 1-3 hours.

**Malware report acceptance:**

- exactly eleven frozen rows, no extras/omissions/duplicates/mismatches;
- any valid `N/11` is published honestly; target behavior-positive detection subscore is 11/11 and
  the target gate fails when `N < 11`;
- every positive matches a frozen general behavior class rather than identity/reputation;
- detection, completion/quality, safety, and overall status shown independently; and
- 11/11 described as a known-regression gate, never broad malware coverage.

**Benign report acceptance:**

- forty current Q01 rows;
- false-malicious and review/unsupported/infrastructure friction by artifact form;
- clean neighbors reported separately;
- no unresolved row omitted or called clean; and
- ground truth and confidence limits visible.

## 13. Detection-alpha handoff

### A01 - Coherent local detection alpha

**User outcome:** A developer can build/install WhoaThere, run preflight/readiness, inspect an exact
artifact, understand `BLOCK` versus `REVIEW`, and reproduce the inert demo from one concise guide.

**Budget:** 2-4 hours.

Link P04/R06/Q06 reports with their honest claim boundaries. README remains upbeat,
portfolio-ready, and accurate.

### A02 - Clean-Mac inert VM smoke

**User outcome:** A prospective user can follow the guide on a clean supported Apple Silicon Mac
without repository knowledge.

**Budget:** 2-4 hours.

**Acceptance:**

1. Install/build, preflight, inspect, human/JSON output, and teardown work.
2. One inert exact artifact executes guest-only in a fresh VM with digest continuity.
3. VM stop, clone destruction, no public route, and no sync-back are proven.
4. No raw malware reaches the local Mac.
5. A sanitized transcript becomes the alpha handoff.

A02 completes the reset goal. Mutation, held-out malware, 120-artifact benign qualification,
Claude arbitration, adaptive probes, cloud backends, and clean-admission completion begin only
under a separately approved follow-on plan.

## 14. Parking lot

- Sensitive-source-to-HTTPS WIP experiment.
- General verified-evidence registry prototype.
- Complete multimodality clean-admission denominator.
- Partial-evidence recovery on failed VM paths.
- Static prompt tuning around one inert flow.
- Legacy/ZIP-sdist breadth without a measured blocker.
- Adaptive probes and Claude as second provider.
- Mutation, held-out, and 120-artifact qualification.
- Cloudflare, Firecracker, AWS, multi-tenant, GUI, installer, and enterprise integrations.

An item leaves the parking lot only when a current frozen criterion fails and it is the smallest
demonstrated remedy.

## 15. Decision rule

Choose the next action that most directly improves one visible number:

1. exact artifact forms with understandable user verdicts;
2. previous misses product-blocked out of four;
3. diagnostic known-regression detections out of eleven;
4. final frozen-build detections out of eleven;
5. benign artifacts measured out of forty;
6. false-malicious/friction rates; or
7. safety violations, which must remain zero.

If an action cannot name the number and user-visible artifact it will produce within four hours,
it is not the next chunk.
