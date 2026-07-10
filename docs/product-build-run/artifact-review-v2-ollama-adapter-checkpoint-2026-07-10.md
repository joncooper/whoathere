# Artifact Review v2 Pinned Local Ollama Adapter Checkpoint

Date: 2026-07-10

Status: verified inert-protocol implementation for a pinned, literal-loopback local AI provider;
not a live-model qualification, complete AI-review, malware-detection, VM, telemetry, admission, or
release-readiness claim

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact Review v2 Contract Checkpoint](artifact-review-v2-contract-checkpoint-2026-07-09.md)
- [Artifact Review v2 Local Runtime Checkpoint](artifact-review-v2-local-runtime-checkpoint-2026-07-09.md)
- [Artifact Review v2 Authenticated Evidence Checkpoint](artifact-review-v2-authenticated-evidence-checkpoint-2026-07-09.md)

## Executive summary

WhoaThere now has a measured-adapter seam for sending exact Artifact Review v2 work items to a
pre-existing Ollama service at the literal IPv4 loopback endpoint `127.0.0.1:11434`. The adapter
accepts only the canonical artifact-bound provider-input wire format, keeps fixed review
instructions in the system role and package-controlled content in a structured user-data role,
requests a non-streaming schema-constrained response with pinned inference settings, and rejects
unbounded, truncated, drifted, redirected, compressed, or otherwise unsupported responses.

The local runtime independently reparses the adapter's bounded terminal frame before it can record
separate trusted and untrusted channels. The authenticated-evidence layer repeats that parsing and
verification from restricted stdout, stderr, and exact provider-input bytes before signing. The
aggregate manifest binds the observation and carries explicit limitations for the unattested
loopback peer, server-reported model digest, unmeasured weights and server executable, unenforced
server egress and resources, and unverified server-side cancellation.

This checkpoint used only inert npm bytes, synthetic model output, and an in-process fake loopback
server. It did not contact a live model, install or execute package code, or access the restricted
eleven-sample corpus. A model response remains advisory: a finding may contribute to a block, but a
`no_finding` response cannot authorize allow or sync-back.

## Exact provider-input boundary

The detector now exposes a strict decoder for the canonical provider-input bytes produced by an
artifact-bound invocation. The decoder:

- enforces the provider-input byte cap before parsing;
- denies unknown and duplicate fields, trailing data, and noncanonical JSON encodings;
- requires the exact trusted system prompt and model-output schema text;
- reconstructs the invocation and revalidates the request, artifact, manifest, coverage, work-item,
  file, chunk, byte range, line range, selected-content digest, and context references; and
- reserializes the validated value and requires byte-for-byte equality with the input.

The returned validated type redacts package source from `Debug`. The adapter receives that type,
not an arbitrary caller-provided prompt.

## Role-separated Ollama request

For each work item, the adapter emits exactly two chat messages:

1. a fixed system message containing the Artifact Review v2 instructions; and
2. a canonical JSON user message containing the explicit trust-boundary label, exact identities,
   ranges and contexts, plus the package-controlled source text.

The role-mapping contract, each message, and the complete API request have separate SHA-256
identities. The request sets `stream: false`, `think: false`, `keep_alive: 0`, the exact JSON schema
as `format`, and the request-bound seed, temperature, top-p, context-token, and output-token caps.
The package cannot choose the endpoint, message roles, trusted instructions, result schema, or
inference settings.

This is structural role separation at the adapter boundary. It does not attest that an untrusted
Ollama server or model template honored those roles internally, so the signed evidence retains the
`ollama_server_role_semantics_not_attested` limitation.

## Loopback transport and model observation

The adapter uses a direct Rust TCP connection to the literal `127.0.0.1:11434` address. It does not
perform DNS lookup, consult proxy variables, follow redirects, or accept transfer encoding or
compressed responses. HTTP headers and bodies are independently capped; a successful response
must be HTTP/1.1 JSON with one valid `Content-Length` matching the complete body.

Before and after the chat request, the adapter reads `/api/version` and `/api/tags`. Exactly one
model must match both the requested `name` and `model`, and its server-reported manifest digest must
equal the pinned expected digest before and after generation. Version or digest drift fails the
invocation. The response must identify the same requested model, use the assistant role, finish
with `done: true` and `done_reason: stop`, remain within both byte and token caps, and contain no
thinking text, images, or tool calls.

The wire decoder follows the documented `/api/tags` shape in which `details.parent_model` may be
absent and validates its empty default. It otherwise stays deliberately strict. This compatibility
was checked against the current official [list-models](https://docs.ollama.com/api/tags) and
[chat](https://docs.ollama.com/api/chat) API contracts.

The observed digest is still asserted by the loopback server. It is not an independent hash of all
model blobs or a measurement of the loaded weights. A same-user process can impersonate the
loopback service. The `LocalOnly` request posture describes the requested destination; it does not
prove that the server did not log, cache, forward, or otherwise disclose source.

## Terminal frame and authenticated reconstruction

On successful generation, the adapter writes model output to stdout and one bounded terminal frame
to stderr after a fixed ready marker. The frame binds:

- adapter id and version, endpoint, and server version;
- work-item, invocation, and provider-input identities;
- requested and response model names;
- expected, pre-run, and post-run model-manifest digests;
- system-message, user-message, role-mapping, and API-request digests;
- raw API-response and model-output digests and output length;
- prompt and output token counts, stop reason, and all inference settings; and
- the explicit loopback-transport and server-reported-model postures.

The runtime accepts a completed Ollama invocation only after it regenerates the exact request and
message digests and checks the frame against the captured stdout and provider input. A missing,
malformed, substituted, or inconsistent frame becomes a failed capture with collapsed channels and
unverified model identity. It cannot be normalized as a completed review.

The authenticated-evidence verifier performs the same reconstruction again from restricted
material. The authenticated aggregate schema and runtime-contract identity advance to v3 and bind
the adapter version, terminal-frame schema, and typed observation. The raw API-response digest is
preserved as an adapter observation; because the raw HTTP body is not separately captured by the
outer runtime, that particular digest is not independently recomputed by the evidence verifier.

No path in this slice grants package-admission or sync-back authority. Incomplete coverage,
provider failure, a clean-looking response, and even a completely authenticated observation all
retain `can_authorize_allow() == false`.

## macOS process-control stabilization

Repeated runtime testing exposed a second macOS process-group transition: under concurrent process
churn, `kill(-pgid, signal)` can return `EPERM` for a dedicated group created and verified by the
runtime. The cleanup guard now reconciles independent `waitid` leader state and `libproc`
process-group membership. It falls back to signaling the owned, unreaped child PID only when the
leader is live and provably the sole group member. Any descendant, exited-leader inconsistency, or
later nonempty group still fails cleanup.

Cleanup success continues to require an independently observed leader exit, an empty group, closed
pipes, and bounded reap. The fallback does not treat `EPERM` as success and cannot silently skip a
known descendant.

## Verification

The stabilized slice passed these gates on 2026-07-10:

| Gate | Result |
| --- | --- |
| Focused detector, adapter, runtime, and authentication tests | 95 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 673 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting check | passed |
| `git diff --check` | passed |
| Diagnostic-free repeated output-cap cleanup path | 32/32 passed |
| Diagnostic-free repeated timeout/descendant-cleanup path | 32/32 passed |

The adapter tests prove canonical request stability, package-text/system-role separation, strict
provider-input decoding, exact fake-server request flow, model-digest mismatch rejection before
chat, truncation rejection, redirect rejection, terminal-frame verification, and tampered-stdout
rejection. Runtime and authentication tests prove that a valid inert terminal observation is
carried into signed evidence while a tampered observation becomes failed, uncertain evidence.

These are contract and containment-adjacent tests, not detection-quality measurements. They do not
qualify a real model, establish recall or false-positive performance, or satisfy the known-malware,
benign-friction, or held-out-generalization gates.

## Explicit non-guarantees and next gate

This checkpoint does not provide or claim:

- a measured or protected Ollama server process;
- an independently hashed model-weight closure;
- proof that server-side role semantics, privacy, egress, caching, resource limits, or cancellation
  matched the adapter request;
- complete multi-pass review, version-diff analysis, or model-quality qualification;
- package detonation, independently protected process/file/network telemetry, or verdict authority;
- broad npm or PyPI malware detection; or
- restricted-malware regression, benign-friction, held-out, beta, or cloud-backend readiness.

The next implementation gate is Phase 4's first typed, exact-artifact scenario: deliver a digest-
checked inert npm tarball to a disposable macOS VM, install it into a clean offline consumer project
with lifecycle scripts enabled, exercise the applicable trigger surface, capture bounded evidence,
prove teardown, and keep sync-back structurally unrepresentable. Wheel and sdist scenarios follow
only after that first slice proves the shared transport and scenario contracts.
