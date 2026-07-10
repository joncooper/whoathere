# Artifact Review v2 Authenticated Evidence Checkpoint

Date: 2026-07-09

Status: stable authenticated-evidence contract with a sealed, bounded MemoryOnly authority; not a
protected-authority, telemetry, VM, malware-detection, admission, or release-readiness claim

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Threat-Model Addendum](artifact-native-threat-model-addendum.md)
- [Artifact Review v2 Contract Checkpoint](artifact-review-v2-contract-checkpoint-2026-07-09.md)
- [Artifact Review v2 Deterministic Normalizer Checkpoint](artifact-review-v2-normalizer-checkpoint-2026-07-09.md)
- [Artifact Review v2 Local Runtime Checkpoint](artifact-review-v2-local-runtime-checkpoint-2026-07-09.md)
- [Artifact Review v2 Replay And Lineage Authority ADR](artifact-review-v2-authority-store-adr-2026-07-09.md)

## Executive summary

WhoaThere now has a stable authenticated Artifact Review v2 evidence slice for the macOS local inert
provider workflow. A host-control-plane signing key can sign a bounded canonical evidence statement
only for a runtime whose evidence identity was bound to a challenge before execution. The verifier
independently validates the captured runtime material, deterministically re-normalizes provider
output against the exact request and normalized artifact, reconstructs the expected statement,
checks Ed25519 provenance and freshness, and atomically applies the bounded in-memory replay and
artifact-lineage transition. The sealed authority exposes only the MemoryOnly backend in this
slice; callers cannot substitute an always-accepting implementation.

In this checkpoint, **authenticated** has a deliberately narrow meaning: the accepted statement is
byte-for-byte the verifier-constructed statement signed by a configured host-control-plane key, and
the one-process memory store accepted its challenge, evidence identity, predecessor, and cumulative
positive set. The authenticated wrapper also carries the authority's typed acceptance commit
receipt, including its authority identity, generation, outcome, and explicit MemoryOnly and
NoRestartOrRollbackProtection posture. It does not mean that the provider executable, model
weights, build, runtime, normalizer, host, or evidence store is independently measured or protected
from the same macOS user. It also does not mean that review coverage is complete or that the
artifact is safe.

Incomplete evidence is intentionally authenticatable. Timeouts, truncation, failed or missing work,
collapsed prompt channels, partial isolation, incomplete coverage, and other limitations remain in
the signed statement rather than preventing provenance from being recorded. Authentication cannot
upgrade any of those conditions to clean. Every signed package and authenticated result returns
`can_authorize_allow() == false`; this slice supplies no package-admission or sync-back authority.

All focused verification used inert fixtures and synthetic provider output. No package lifecycle,
installation, build, import, or entry-point code was executed. No malware was downloaded, opened,
unpacked, inspected, or executed, and the restricted eleven-sample corpus was not accessed.

## Canonical signature and statement profile

The signed statement uses the explicit `ed25519.direct.expected_body.v1` profile. Its signature
input is a domain-separated binary frame containing a layout version, bounded body length, and the
exact canonical body, followed by the 64-byte Ed25519 signature. There is no digest-then-sign mode
whose hash or encoding can be selected by the evidence.

The body is `whoathere.artifact_review_evidence_statement.v2` under the constrained
`rfc8785.jcs.no_numbers.v1` profile. It uses RFC 8785/JCS serialization but represents integer
values as validated decimal strings and explicit optional states as tagged objects. The statement
contains no JSON numbers or `null`, has closed typed projections, and is capped at 256 KiB. This
reduces cross-language numeric and absent-value ambiguity while keeping the signed bytes directly
auditable.

Verification does not parse untrusted statement JSON into a trusted domain object. Instead, the
verifier reconstructs the expected typed statement from trusted inputs and validated captured
material. It resolves the expected key identity, checks key activation, expiry, and revocation,
checks evidence freshness, and verifies the Ed25519 signature over the received framed body. Only
after signature verification succeeds does it canonicalize the verifier-owned expected statement
and require an exact byte comparison with the received body. A valid signature over a different
canonical body is therefore rejected.

## Challenge and exact execution binding

Each MemoryOnly authority lifetime first creates a caller-inaccessible 256-bit identity directly
from the operating system CSPRNG. That authority id is included in the canonical challenge binding,
the authority-aware runtime-execution-binding digest, the restricted evidence material, the
aggregate manifest, and the signed statement. A challenge or evidence package from another
authority lifetime therefore fails binding checks even if its other identifiers look the same.

Challenge ids include a separate fresh 32-byte nonce from the operating system CSPRNG, domain
separation, the authority identity, and the canonical challenge binding. Entropy failure is fatal.
Each challenge is bounded to at most 15 minutes and commits to:

- the authority id;
- the evidence id and run id;
- original artifact, acquisition envelope, normalized manifest, and canonical quarantine CAS
  object identities;
- policy and complete Artifact Review request digests;
- the ordered expected work-set digest and exact work-item count;
- trust domain, issuer, host-control-plane role, restrictive-advisory purpose, algorithm, key id,
  and key epoch;
- the artifact-derived lineage scope and explicit predecessor evidence digest; and
- challenge issuance and expiry.

The request and final statement extend this binding through the deterministic-analysis and coverage
manifest digests; provider-adapter and model-content digests; prompt-template digest; model-output
and adapter-result schema digests; declared control-plane build digest; runtime and normalizer
contract digests; aggregate-manifest and normalized-result digests and lengths; execution-claims
digest; current and cumulative finding identities; completeness; and limitations.

The runtime seam accepts a `LocalProviderEvidenceExecutionBindingV2` before execution and returns a
distinct `EvidenceBoundLocalProviderRunV2`. That type carries the exact challenge, evidence, run,
and challenge-binding identities plus host-observed start and finish times. The authority id is
supplied separately to the canonical runtime-seam digest and rechecked against the challenge and
restricted material. The signing API accepts only this evidence-bound host-timed type; the old
unbound `LocalProviderRunV2` does not type-check at the signing boundary. The run must fall after
challenge issuance and before evidence issuance, and the short-lived evidence must expire no later
than the challenge.

This is freshness and identity binding, not trusted-time attestation. Challenge issue and expiry
times are still supplied by the caller before the in-memory store issues the challenge. Runtime and
evidence times are read from the host clock, but no protected authority currently owns the complete
time sequence.

## Independent capture reconstruction

Signing and verification do not trust a caller-supplied aggregate digest as a substitute for raw
evidence checking. The restricted in-process material contains invocation records, bounded stdout
and stderr captures, the work partition, terminal state, aggregate manifest, and normalized result.
The verifier reconstructs the evidence independently by:

1. revalidating the artifact-review request against the evidence subject, normalized artifact, and
   deterministic analysis;
2. requiring the runtime work partition to match the request's complete ordered work-item set;
3. checking every recorded work-item, request, invocation, provider-adapter, model-content,
   provider-input, stdout, and stderr identity, length, and digest;
4. deriving provider-output status from the recorded termination reason and checking coherent EOF
   claims;
5. rebuilding typed completed, truncated, or failed provider outputs from the bounded captured
   bytes;
6. rerunning the deterministic normalizer against the exact normalized artifact bytes and request;
7. deriving current positive finding ids, limitations, completeness, aggregate manifest, and the
   expected signed statement; and
8. requiring exact equality with the carried normalized result and aggregate manifest.

The signed evidence includes terminal and work-partition state rather than authenticating only the
successful prefix. Expected, recorded, attempted-without-capture, and unattempted work are
distinguished. Terminal error, terminal phase, bound work-item id, secondary cleanup error, and
run-directory cleanup status are preserved. Failed, truncated, missing, or unattempted work remains
signed uncertainty and cannot be reinterpreted as completed review.

## Replay, lineage, and positive preservation

Issue is now a state transition, not merely random challenge construction. Before provider
execution, the authority looks up `(trust_domain, evidence_id)` and commits a `Pending` reservation
together with the new challenge. An exact retry of the same pending binding returns the same
challenge, the same generation, and an `IdempotentRetry` issue receipt. A different binding for the
same reserved evidence id, or reuse of an accepted id, is rejected as replay or equivocation before
execution begins. Issuer and signing-key rotation inside the trust domain cannot bypass that
reservation.

Challenge consumption is the final verification step. Request validation, capture reconstruction,
deterministic re-normalization, expected-statement construction, key and freshness checks, Ed25519
verification, and exact expected-body comparison all succeed before the in-memory store can mutate.
Only then does one locked transition advance the existing `Pending` reservation to `Accepted` and
compare-and-swap the lineage head.

An exact retry of the same accepted challenge, evidence digest, current positives, and cumulative
positive set returns the existing generation with an `IdempotentRetry` acceptance receipt; changed
evidence or findings are replay or equivocation.

Lineage is keyed by trust domain and a scope derived only from the exact artifact SHA-256. The
challenge must name the current predecessor evidence digest, or absence for the first result. A
competing or stale successor fails the compare-and-swap. The accepted cumulative positive set must
be exactly the union of the predecessor's retained positives and the current run's validated
positive finding ids. A later empty or cleaner review cannot erase an earlier positive; clearing a
false positive requires a separate adjudication design.

The state engine uses deterministically ordered `BTreeMap` and `BTreeSet` values. Issue and
acceptance transitions take the current state by reference and construct a cloned next state only
for a successful new transition. The mutex-protected backend replaces current state only after the
transition succeeds; validation, capacity, replay, lineage, freshness, and generation errors leave
the old state unchanged.

Current hard caps are:

| Authority resource | Maximum |
| --- | ---: |
| Active `Pending` challenges | 4,096 |
| `Pending` plus `Accepted` evidence reservations | 16,384 |
| Artifact lineages | 4,096 |
| Positive finding identities in one lineage or reservation set | 4,096 |
| Positive finding references across reservations and lineages | 65,536 |
| Authority generation | 9,007,199,254,740,991 |

Capacity and JCS-safe-generation exhaustion fail before mutation; the authority does not prune a
reservation or lineage implicitly. Issue and acceptance return typed commit receipts containing the
CSPRNG authority id, generation, transition outcome, `MemoryOnly` durability, and
`NoRestartOrRollbackProtection`. A new issue or acceptance increments the generation; an exact
idempotent retry reports the already committed generation. The authenticated wrapper exposes the
acceptance receipt rather than reducing authority state to a caller-supplied boolean.

These properties remain process-local. The state is bounded but is not durable, restart-safe,
cross-process, rollback-resistant, or protected from a same-user process. Receipts contain no
canonical state digest and cannot be recovered after process loss. The linked authority-store ADR
defines the required crash-consistent and protected Mac evolution without upgrading this
checkpoint's claims.

## Key lifecycle boundary

Verification keys are resolved by the complete trusted identity: trust domain, issuer, producer
role, evidence purpose, algorithm, key id, and key epoch. Weak Ed25519 verification keys are
rejected. Evidence must be issued and expire inside the key's activation window, current
verification time must remain inside that window, and revocation applies to both evidence issuance
and verification time.

The implementation accepts a caller-provided 32-byte signing seed and zeroizes that input buffer
after constructing the key. It does not generate keys, store them in the Keychain or Secure
Enclave, restrict signing to a protected service, rotate them operationally, or guarantee that all
derived key material is zeroized from memory. The registry and signing object are development
primitives, not protected key custody.

## Focused verification

The focused gates for this stabilized slice passed on 2026-07-10:

| Component | Unit | Integration | Compile-fail | Result |
| --- | ---: | ---: | ---: | --- |
| macOS local runtime | 7 | 15 | 1 | passed |
| Artifact Review authentication | 11 | 4 | 1 | passed |

The compile-fail checks enforce the type boundary that prevents an unbound runtime result from
being treated as evidence-bound. Strict Clippy with warnings denied, rustdoc with warnings denied,
Rust formatting, and `git diff --check` also passed for the focused slice.

The macOS cleanup path was additionally exercised with 16 concurrent exact timeout/cancellation
runs and 16 concurrent exact stdout/stderr-cap runs; all 32 passed. This stress exposed and then
closed a libproc/waitid transition race: a child leader can exit between the separate leader and
process-group observations, and macOS can omit the still-waitable zombie from the group query. The
runtime now records that transition without treating it as lost control, while cleanup still
requires an independently observed leader exit, an empty remaining process group, and verified
pipe termination before it can emit a captured invocation record.

The full workspace regression gate subsequently passed 663 unit, integration, and doc tests with
zero failures, including both compile-fail API boundaries. Workspace Clippy with warnings denied,
rustdoc with warnings denied, Rust formatting, and `git diff --check` also passed. These gates prove
repository compatibility; they do not upgrade any provider, VM, telemetry, malware-detection, or
release-readiness claim.

## Explicit non-guarantees

This checkpoint does not provide or claim:

- durable, restart-safe, cross-process, tamper-evident, same-user-protected, or rollback-resistant
  authority state; the current bounded authority is in-memory and non-durable;
- a canonical persisted authority-state encoding or state digest, receipt recovery after process
  loss, expired-reservation tombstones, explicit maintenance, or safe reclamation;
- authority-stamped challenge issue times; challenge issuance and expiry are caller-supplied;
- protected signing-key generation, storage, use, rotation, or recovery;
- an external protected transport or custody mechanism for restricted captures, normalized output,
  credentials, canaries, or other restricted material;
- independently measured control-plane build, runtime binary, or normalizer binary identities; the
  current build identity is declared and the runtime/normalizer identities are contract digests;
- exclusion of the documented same-user staged-provider executable race;
- a host, filesystem, process-count, memory, CPU, file-size, or network sandbox;
- comprehensive raw-capture or duplicate-buffer memory zeroization;
- VM execution, package install/build/import/entry-point/lifecycle execution, or guest telemetry;
- a real provider/model qualification or any model-quality guarantee;
- malware detection, restricted-corpus regression, benign-friction, held-out, or detection-quality
  qualification; or
- allow, admission, install, or sync-back authority.

Authentication proves neither completeness nor safety. A signed `Incomplete` statement remains
authenticated and incomplete. A signed empty result remains uncertain. A signed positive may
support blocking or escalation, but no authenticated Artifact Review v2 value can authorize allow.

## Remaining gate

`AN-506` remains open pending protected authority and protected telemetry. The next implementation
must move challenge issuance, trusted time, signing-key use, replay/lineage state, and acceptance
commit behind a durable protected Mac authority, then bind protected sensor health and scenario
telemetry into the evidence envelope and pass the cloud-Mac durability, replacement, rollback, and
client-identity qualification gate defined by the authority-store ADR.

Until that work lands, this checkpoint is a stable cryptographic and state-transition contract for
restrictive advisory Artifact Review evidence, not completion of the canonical plan's authenticated
dynamic-evidence gate.
