# Artifact Review v2 Contract Checkpoint

Date: 2026-07-09

Status: provider-independent contract checkpoint; not a provider integration, detection-quality, or
release-readiness claim

Canonical plan:
[Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

## Executive summary

WhoaThere now has an Artifact Review v2 contract that prepares exact normalized npm tarball, PyPI
wheel, and PyPI source-distribution content for later AI-assisted review. It inventories every
normalized member, selects bounded text chunks as exact byte ranges, creates artifact- and
request-bound work items, separates trusted review instructions from package-controlled data, and
strictly validates adapter-normalized findings back to the selected bytes.

This checkpoint is deliberately narrower than an AI review implementation. There is no provider
adapter, model invocation, network call, or model execution in this slice. The resulting findings
are structurally validated advisory observations only. They are unauthenticated, cannot authorize
an allow decision, and do not change the product's detection-quality claim.

All work represented here used inert archive fixtures and synthetic adversarial text. No malware
was downloaded, accessed, unpacked, inspected, or executed.

## Current contract

### Exact artifact inventory and selection

The review request is built from an already validated evidence subject, normalized artifact, and
deterministic static analysis. It binds the original artifact digest, acquisition-envelope digest,
normalized manifest digest, quarantine object key, policy digest, and deterministic-analysis
digest.

Coverage is constructed over **every normalized file**, not only members already classified as
source or as executable by package metadata. This accounts for npm lifecycle and extensionless
targets, wheel metadata and entry points, `.pth` files, data scripts, deep Python modules, sdist
build metadata and backends, shell helpers, and other normalized text surfaces. Native members
identified by manifest, extension, language classification, or magic remain in the inventory but
are marked `NativeInventoryOnly`; invalid text and size or work-budget exclusions are also explicit
rather than silently omitted.

Selected UTF-8 text is partitioned into contiguous chunks of at most 32 KiB. Each chunk records its
absolute normalized-file byte range, line range, selected-byte SHA-256, and stable chunk id. Normal
chunks prefer newline boundaries; overlong or minified lines use UTF-8-safe hard boundaries. The
invocation re-reads the selected range from the normalized artifact and rehashes it before exposing
the bytes, so a work item refers to the exact bytes represented by its coverage entry. The current
chunk-local passes cover trigger surfaces, credential/filesystem behavior, network/exfiltration,
process execution, obfuscation, and environment gating.

Request construction applies limits to the final plan, not just its intermediate indexes. The
200,000-reference coverage-context ceiling counts both deterministic trigger references and the
fallback `InventoryOnly` references created for otherwise unconnected files. A request is also
rejected if it would create more than 512 work items or resend more than 8 MiB of source across all
chunk/pass invocations. The latter accounts for each exact chunk once per required pass, preventing
a modest selected-byte inventory from expanding into unbounded repeated model input.

### Trusted instructions and untrusted package bytes

Each invocation keeps the fixed system prompt and strict schemas in the trusted side of the
contract. Normalized paths, language, trigger or inventory context, and exact package bytes are
carried separately as untrusted data. Package content is not interpolated into the trusted prompt,
and debug or request formatting does not emit selected artifact bytes.

The contract has two intentionally different result shapes:

- The **model-facing schema** asks for semantic findings against one work item using
  chunk-relative byte ranges. It does not ask a model to invent file hashes, line numbers, or an
  evidence digest.
- The **adapter-normalized schema** requires exact artifact, request, provider, model, prompt, and
  schema bindings plus resolved file/chunk/context references, absolute byte and line ranges,
  selected-byte hashes, and evidence hashes.

That split keeps deterministic byte accounting in the future adapter instead of pretending a
language model can reliably reproduce cryptographic or archive-derived values. The adapter itself
is not implemented in this checkpoint.

### Reproducibility bindings

The request and invocation bind the selected provider-adapter identity and digest, pinned model id,
version and content digest, fixed prompt identity and digest, model-output and adapter-result schema
digests, privacy posture, and all current inference settings, including seed, temperature, top-p,
context limit, and output limit. They also bind the request digest and coverage-manifest digest to
the exact artifact, manifest, policy, and deterministic analysis.

The current canonical JSON is a deterministic local Rust/Serde projection. It is useful for this
contract's local digests, but it is not yet the cross-language canonical authenticated evidence
wire.

The immutable request digest is computed once when the request is constructed and cached outside
the serialized projection. Request validation rechecks that cache against the canonical bytes.
Invocation, per-work-item claim, report, and decode paths then reuse the cached digest, avoiding
request-size multiplication when a bounded plan contains many work items.

### Result trust boundary

`ArtifactReviewExecutionReportV2` records caller-supplied claims about a future adapter run. It
binds the request and the adapter-normalized output digest. Each reported work item has one unique
execution claim containing its work-item id, exact invocation digest, provider raw-output digest,
status (`Completed`, `Truncated`, or `Failed`), claimed prompt-channel isolation, and claimed
no-truncation status. The invocation digest derives from the request digest and work-item id, so it
also commits to that work item's chunk, contexts, pass, provider, model, prompt, schemas, and
inference settings. The report sorts the claims deterministically, rejects duplicate work-item
claims, and records a SHA-256 over the complete normalized claim set in addition to the separate
adapter-normalized output digest.

These are still control-plane assertions, not attestations. Public constructors make both the
per-work-item claims and aggregate report **unauthenticated**: neither the raw-output digests nor the
status, channel-isolation, and no-truncation fields prove that a provider ran or that a particular
model produced complete bytes. A future authenticated evidence layer must establish those facts.

The strict decoder rejects unknown fields, duplicate fields, synonyms, echoed or trailing content,
oversized output, binding substitutions, unknown or incomplete work-item references, invalid
ranges, and selected-byte or evidence-digest mismatches. Accepted findings are named and exposed as
structurally validated findings. They are still untrusted advisory model content and must be
sanitized before display. Only a claim with `Completed` status can support a referenced finding;
truncated, failed, omitted, or duplicated work cannot be treated as completed review.

This layer has asymmetric authority:

- one or more structurally valid findings can derive an advisory `Suspicious` result;
- zero findings always derive `Uncertain`, even when the caller claims every current work item ran;
- `NoFinding` is rejected at this checkpoint; and
- no structurally validated result can authorize allow.

## Deliberately incomplete coverage

Artifact Review v2 currently marks coverage incomplete by construction. The following limitations
are encoded in the coverage manifest rather than left as informal caveats:

- aggregate graph context is not implemented;
- aggregate synthesis is not implemented;
- previous-version acquisition and version-diff context are not implemented;
- actual tokenizer-budget accounting is not verified;
- provider execution and provider attestation are not implemented;
- raw model-output normalization into the exact adapter schema is not implemented; and
- a cross-language canonical authenticated wire is not implemented.

Additional normalization, deterministic-analysis, native-code, invalid-text, excluded-member, and
resource-limit gaps are propagated per artifact and per file. These limitations are why absence of
a finding cannot be interpreted as clean, safe, or admissible.

## Focused verification

The focused offline integration run for this checkpoint passed 15 inert-fixture tests with zero
failures:

| Suite | Result | Scope |
| --- | ---: | --- |
| `artifact_review_v2` | 13 passed | inventory, exact chunking, prompt/data separation, request/invocation/claim digest bindings, execution-cost ceilings, strict result decoding, fail-closed references, and structural finding validation |
| `artifact_review_ecosystems_v2` | 2 passed | exact wheel and normalized-sdist semantic surfaces, deep chunk tails, extensionless text, native inventory, and rejection of false clean results |

Command used:

```sh
cargo test -p whoathere-detector \
  --test artifact_review_v2 \
  --test artifact_review_ecosystems_v2 \
  --offline
```

The final offline workspace gate also passed 613 tests with zero failures, and workspace Clippy
passed with warnings denied. Detector rustdoc passed with warnings denied; Rust formatting and
`git diff --check` were clean. These are implementation gates, not detection-quality qualification.
Smoke harnesses, benign qualification, held-out evaluation, provider execution, VM execution, and
the restricted malware regression gate are not claimed by this checkpoint.

## Next steps

1. Implement a local, provider-specific adapter that preserves trusted/untrusted channel separation,
   captures exact raw output and status per invocation, deterministically normalizes chunk-relative
   findings, and fails closed on truncation, malformed output, or incomplete work.
2. Add a bounded cross-language wire plus authenticated evidence, trusted producer/key resolution,
   freshness, and atomic replay protection before any result can participate in admission.
3. Stage the exact artifact into a disposable guest, rehash it inside the guest, and return an
   authenticated receipt before adding typed npm, wheel, and sdist detonation scenarios and
   protected behavioral telemetry.

Only after those foundations and the benign/held-out gates are in place should the separately
approved restricted corpus be rerun. Nothing in this checkpoint authorizes execution of real
malware.
