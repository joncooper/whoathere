# Artifact Review v2 Deterministic Normalizer Checkpoint

Date: 2026-07-09

Status: provider-independent deterministic-normalization checkpoint; not a provider-runtime,
authenticated-evidence, detection-quality, VM, or release-readiness claim

Canonical plan:
[Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

Prior checkpoint:
[Artifact Review v2 Contract Checkpoint](artifact-review-v2-contract-checkpoint-2026-07-09.md)

## Executive summary

WhoaThere now has a deterministic adapter-side normalizer for Artifact Review v2. Given a validated
artifact-review request and bounded provider-output captures attributed to its exact work items, it parses a
small strict model-output schema, resolves chunk-relative references against trusted normalized
artifact bytes, derives the absolute byte and line ranges and evidence digests itself, emits the
strict adapter-result shape, and runs that result through the independent structural decoder.

This closes the provider-output-normalization gap recorded in the prior contract checkpoint. It does not
run an AI provider or model. It also does not authenticate that a provider ran, that the named model
produced a response, or that the claimed channel isolation and non-truncation properties are true.
The execution report remains explicitly unauthenticated, every normalized result remains advisory,
and `can_authorize_allow()` remains unconditionally false.

All verification in this slice used inert archive fixtures and synthetic adversarial JSON. No
malware was downloaded, opened, unpacked, inspected, or executed. The restricted eleven-sample
corpus was not accessed or run.

## Implemented boundary

The slice is intentionally split into three roles:

1. The existing request builder inventories normalized artifact files, binds exact selected chunks
   and deterministic context, and constructs one work item for each required chunk-local pass.
2. A future provider runtime will execute those invocations and return a typed bounded capture plus
   status, channel-isolation, and truncation observations.
3. The new deterministic normalizer accepts those captures, resolves only valid references, and
   emits the exact adapter-result JSON and execution report consumed by the existing independent
   structural decoder.

Only roles 1 and 3 exist here. No provider process, model process, HTTP client, model server, or
provider SDK is invoked by this implementation. Provider captures in the focused tests are inert bytes
constructed inside the tests.

## Exact invocation and schema binding

Each model-facing response must contain all of the following and no unknown fields:

- the exact `whoathere.artifact_review_model_output.v2` schema version;
- the assigned work-item id;
- the expected invocation SHA-256;
- one of the closed advisory verdict enums; and
- a bounded list of findings using closed category, severity, context-kind, chunk-relative range,
  and explanation fields.

The invocation digest is derived from the request digest and work-item id. The request digest
already commits to the exact artifact and normalized-manifest identities, deterministic-analysis
identity, policy, coverage manifest, provider-adapter identity and digest, pinned model identity and
content digest, prompt and schema digests, privacy posture, and inference settings. Consequently, a
response capture from the same-looking work item cannot be replayed across a request whose model or
inference settings changed.

Parsing is strict and consumes the complete non-truncated capture. Malformed JSON, unknown fields, duplicate
fields, prose or code fences around JSON, and trailing JSON are not salvaged. Package-controlled
text and model text remain untrusted data; neither can alter the trusted prompt, schema, request, or
artifact bindings.

The model-declared verdict is not trusted as the aggregate result. The normalizer derives
`Suspicious` only from one or more concrete findings that survive exact evidence validation. With
no such findings it derives `Uncertain`, regardless of whether a model declared `no_finding`,
`uncertain`, or unsupported suspicion.

## Deterministic evidence derivation

For each finding, the normalizer resolves the response against the assigned work item and trusted
coverage manifest. It verifies that:

- the referenced context id and kind belong to the exact file coverage entry;
- the chunk belongs to the assigned work item;
- the relative range is non-empty, inside the exact selected chunk, and aligned to UTF-8 character
  boundaries;
- the explanation is non-empty, contains no control characters, and is at most 512 Unicode
  characters; and
- the normalized file and chunk bytes are still present under their bound identities.

It then derives, rather than accepts from the model:

- the absolute file byte range;
- start and end line numbers;
- the SHA-256 of the exact selected byte slice;
- file, chunk, context, work-item, request, provider, model, prompt, and schema references; and
- the final evidence SHA-256 over the complete structured evidence input.

Findings are deduplicated and ordered deterministically by evidence digest. A digest collision with
different evidence is a hard normalization error. The generated adapter-result JSON is immediately
fed to `decode_and_structurally_validate_artifact_review_result_v2`; a result that cannot pass that
independent exact-byte validation is not returned as a successful normalization.

Debug formatting records hashes, sizes, statuses, and counts while redacting captured provider bytes and
the normalized JSON body. Explanations remain bounded untrusted display text and still require
presentation-layer sanitization.

## Failure isolation and positive preservation

Known work-item failures are represented per item wherever safe, instead of turning an unrelated
validated positive into a batch-wide negative result:

- a provider-declared failure contributes no finding and becomes a `ProviderFailed` outcome;
- a bounded captured prefix is constructed explicitly as `Truncated`, contributes no finding, and
  records the prefix digest and byte length without pretending it is a digest of the full stream;
- construction rejects a capture above 256 KiB before hashing it; the future runtime must stop at
  the cap and return a bounded truncated prefix rather than drain or hash an unbounded remainder;
- an aggregate capture-budget overrun contributes no finding and becomes `OutputLimitExceeded`
  with a failed execution claim;
- malformed wire data, binding mismatch, too many findings, invalid context/range evidence, or
  invalid UTF-8 boundaries fail that item atomically; and
- if a later item would exceed the aggregate finding ceiling, that item fails while the already
  bounded and validated suspicious finding set is preserved.

The normalizer records request work items for which no provider output was supplied. Duplicate
outputs, unknown work-item ids, an output count above the planned work-item count, request-binding
failure, digest collision, invalid aggregate execution claims, serialization failure, or failure of
the independent structural self-check remain batch errors because a trustworthy attribution cannot
be constructed.

This asymmetry is deliberate: malformed, failed, truncated, missing, or oversized output can never
be reinterpreted as clean. At the same time, one bad response cannot erase an exact positive from a
different valid response. Zero validated findings always produce `Uncertain`; this layer never
produces an authority-bearing `NoFinding` or allow decision.

## Bounded trigger-first coverage

Request construction now degrades large review plans into explicit partial coverage instead of
aborting the whole request merely because repeated multi-pass work would exceed an execution cap.
Files with deterministic trigger context are considered before inventory-only files, with
normalized path and file id as deterministic tie-breakers. A file is selected only if all of its
current six required chunk passes fit the remaining work-item and repeated-source-byte budgets.

When a reviewable file does not fit, its coverage entry is retained with `WorkBudgetExceeded`, no
work items are emitted for that file, and exact reason codes identify the work-item,
invocation-source-byte, or total-selected-byte budget involved. The aggregate coverage remains
`Incomplete`; the omission cannot silently become clean coverage. Native inventory, invalid text,
oversized files, missing normalized bytes, normalization limitations, and static-analysis
limitations likewise remain explicit.

The 16 MiB repeated invocation-source ceiling is large enough for one maximum-size 2 MiB text file
to run all six current chunk-local passes (12 MiB), while still bounding total repeated model input.
One focused ceiling test confirms that a trigger-connected 1.5 MiB file is selected before a second
1.5 MiB inventory-only file, which is retained as `WorkBudgetExceeded` instead of causing request
construction to fail. A separate 92-file fixture reaches the 512-work-item branch with a
lexically-last `zz-trigger.js` and 90 lexically-earlier decoys. It proves the trigger remains
selected, later decoys are explicitly skipped with no work items, and reversing archive member
order produces the same selected/skipped path sets.

## Enforced ceilings

| Resource | Current ceiling | Behavior at the boundary |
| --- | ---: | --- |
| Normalized files represented by one request | 20,000 | request error above the ceiling |
| Coverage context references | 200,000 | request error above the ceiling |
| Text bytes in one selected file | 2 MiB | explicit `SizeLimitExceeded` coverage |
| Selected text bytes before pass multiplication | 64 MiB | explicit `WorkBudgetExceeded` coverage |
| Chunk size | 32 KiB | contiguous newline-preferred or UTF-8-safe hard chunks |
| Planned work items | 512 | later whole files receive explicit `WorkBudgetExceeded` |
| Source bytes repeated across all planned passes | 16 MiB | later whole files receive explicit `WorkBudgetExceeded` |
| Model context setting | 262,144 tokens | invalid configuration above the ceiling |
| Model output setting | 32,768 tokens | invalid configuration above the ceiling |
| Provider-output capture for one work item | 256 KiB | construction rejects larger input; runtime must return a bounded truncated prefix |
| Provider-output captures accepted across one normalization | 8 MiB | later over-budget items fail as `OutputLimitExceeded` |
| Findings in one item or aggregate result | 256 | item failure; prior bounded positives remain |
| Explanation length | 512 Unicode characters | item fails evidence validation |
| Adapter-normalized result | 1 MiB | normalization error above the ceiling |

These byte limits complement, but do not replace, the future runtime's required wall-clock,
process, memory, cancellation, stdout/stderr streaming, and provider-specific token limits.

## Trust and authority boundary

`ArtifactReviewExecutionReportV2` still contains caller-supplied control-plane assertions. Its
digests make substitutions and internal inconsistencies detectable, but its public construction
does not prove who produced the bytes or whether the claimed provider, model, channel separation,
status, and non-truncation observations are true. Both the report and the structurally validated
result return `is_authenticated() == false`.

Therefore this checkpoint proves deterministic attribution and structural validation, not provider
provenance. A valid finding may contribute advisory blocking evidence. An empty result, completed
claim, or model `no_finding` cannot establish safety. `can_authorize_allow() == false` for every
result, so this slice supplies no authority to admit a package or enable sync-back.

## Focused verification

The three focused detector integration suites passed on 2026-07-09 using only inert fixtures:

| Suite | Result | Covered behavior |
| --- | ---: | --- |
| `artifact_review_normalizer_v2` | 7 passed | exact range/evidence derivation, deterministic ordering, truncation/failure handling, per-item malformed-output isolation, output and finding ceilings, UTF-8 and strict-JSON rejection, independent decoder parity, and cross-request replay rejection |
| `artifact_review_v2` | 14 passed | complete inventory accounting, prompt/data separation, digest and inference binding, exact chunking, trigger-first bounded partial coverage under both source-byte and work-item pressure, strict decoding, uncertain/no-allow behavior, and finding evidence validation |
| `artifact_review_ecosystems_v2` | 2 passed | exact wheel and normalized-sdist semantic surfaces, deep chunk tails, extensionless text, native inventory, and rejection of false-clean results |

Command used:

```sh
cargo test --manifest-path whoathere/Cargo.toml \
  -p whoathere-detector \
  --test artifact_review_v2 \
  --test artifact_review_normalizer_v2 \
  --test artifact_review_ecosystems_v2
```

Result: **23 passed, 0 failed**.

The uninterrupted offline workspace gate also passed **621 tests with 0 failures**, including all
workspace doctests:

```sh
cargo test --workspace --offline
```

Workspace Clippy passed for all targets with warnings denied. Detector rustdoc, Rust formatting,
and `git diff --check` also passed. An independent adversarial review returned `PASS` after checking
binding and replay resistance, positive preservation, schema/runtime parity, UTF-8 and range
validation, honest bounded-capture semantics, trigger-first scheduling, and debug redaction.

These are implementation gates only. This checkpoint does not claim a smoke-harness,
benign-friction, held-out, restricted-corpus, provider, VM, detection-quality, or release-readiness
gate.

## Remaining work

The next implementation work remains substantial:

1. Build a bounded local provider runtime that preserves trusted/untrusted channels, verifies the
   provider executable and pinned model identity, uses a private environment and working
   directories, enforces global and per-invocation deadlines and cancellation, and drains bounded
   stdout and stderr separately without logging raw source or model output.
2. Replace public caller assertions with authenticated evidence: trusted producer/key resolution,
   signed or MAC-bound request/invocation/output-capture/result identities, freshness, replay
   protection, and atomic verification before evidence can affect admission.
3. Finish aggregate graph, version-diff, synthesis, tokenizer-budget, and cross-language canonical
   wire work while keeping incomplete coverage fail-closed.
4. Stage the exact artifact into a disposable VM, independently rehash it inside the guest, compile
   typed npm, wheel, and sdist scenarios, and collect protected process/file/network telemetry from
   a trust boundary the package cannot forge.
5. Integrate verdict policy so unknown, infrastructure error, and malware-detection jobs are
   structurally unable to sync back; preserve zero host execution, unsafe allow, live C2, live
   second-stage fetch, and restricted-evidence leak.
6. Run benign-friction and held-out generalization gates, then use the separately approved
   restricted-lab workflow for the four prior misses and full eleven-sample regression gate.

The available cloud Mac can become useful after the local provider runtime and inert VM scenarios
are integrated: it can provide a clean second Mac host for reproducibility, lifecycle, and telemetry
conformance tests. It must not be used as an informal malware detonation host. Real-malware work
still requires the separate documented restricted-lab approval and custody gate. Cloudflare,
Firecracker/AWS, and other cloud backend qualification remains after the Mac-hosted pipeline is
detection-credible, as required by the canonical plan.
