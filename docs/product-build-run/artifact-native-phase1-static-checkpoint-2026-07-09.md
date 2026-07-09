# Artifact-Native Phase 1 and Static-Analysis Checkpoint

Date: 2026-07-09

Status: implementation checkpoint; not a release-readiness or detection-quality claim

Canonical plan:
[Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

## Executive summary

WhoaThere now has an inert, artifact-native implementation spine for exact npm tarballs, PyPI
wheels, and PyPI source distributions. Quarantined artifact bytes can be reverified, described by an
acquisition-bound `ArtifactEnvelope`, safely normalized into an exact-digest `ArtifactManifest`,
analyzed by the first deterministic artifact detector, and projected into a structurally validated
but explicitly unauthenticated evidence record.

This is meaningful progress on Phase 1 and the beginning of Phase 2. It does **not** complete either
phase's exit gate. In particular, WhoaThere has not yet proven inside a detonation guest that the
executed bytes equal the analyzed bytes, authenticated an evidence envelope, replaced lexical rules
with the planned reviewed language parsers, run the benign qualification cohort, or rerun any real
malware.

All work represented by this checkpoint used inert fixtures and synthetic adversarial inputs. No raw
malware was downloaded, unpacked, inspected, or executed, and this checkpoint does not authorize a
real-malware run.

## Delivered exact-artifact chain

The current host-side data path is:

```text
inert artifact bytes
        |
        v
sealed quarantine CAS object, addressed by original SHA-256
        |
        v
reverified byte lease from the same stored object
        |
        +--> acquisition-bound ArtifactEnvelope
        |        - exact byte digest and length
        |        - magic-detected artifact form
        |        - coordinate, source, method, and custody binding
        |        - resolver/registry metadata digests when required
        |
        v
safe normalization of that lease
        |
        +--> ArtifactManifest
        |        - exact artifact binding
        |        - normalized package identity and member inventory
        |        - npm/wheel/sdist metadata and trigger surfaces
        |        - explicit normalization completeness
        |
        v
deterministic artifact analysis
        |
        +--> trigger graph, coverage, and exact file/range/digest findings
        |
        v
ArtifactEvidenceSubjectV2 and deterministic evidence job
        - artifact, acquisition envelope, manifest, and CAS-object bindings
        - structural validation only; never allow-authoritative
```

The implementation keeps workspace inspection as a separate, explicit subject kind. The legacy
workspace fingerprint is no longer represented as an original artifact hash, and old package-risk
records that used the ambiguous artifact-hash shape are rejected rather than treated as exact-byte
history. Package-risk assessment and store records therefore move to version 2; existing version-1
workspace approvals require reassessment and reapproval instead of an automatic migration.

The runner does not invoke host npm, pip, Python, or package-controlled probe commands for this
path. Its current transport accessor is intentionally described as a verified **host-side transport
source**, not as proof of what a guest received or executed.

## What was implemented

### Exact identity and normalization

- `ArtifactEnvelope` validation binds exact SHA-256 and length to a valid source/acquisition pair,
  canonical UTC acquisition time, custody reference, and required registry provenance digests.
- npm, wheel, and sdist normalizers operate on the verified artifact snapshot and preserve explicit
  completeness and limitation state.
- npm metadata now records the declared `main` target in addition to lifecycle, `bin`, dependency,
  and native-build surfaces.
- Executable-text inventory includes extensionless runtime targets and `.gyp` metadata required to
  account for Node native-build triggers.
- Unsafe archive structures continue to fail closed through path, link, collision, member, depth,
  size, and expansion controls.
- Debug formatting for normalized artifacts and member content is redacted so package bytes,
  metadata, and paths are not casually emitted by diagnostics.

### Sealed quarantine CAS

The persistent quarantine store publishes digest-addressed objects with no-overwrite semantics,
restrictive file and directory modes, and rehash-on-lease verification. It checks expected digest
and length along with owner, mode, link count, directory identity, and symlink/substitution
conditions. An object can be reopened after a process restart without re-resolving its registry
coordinate.

This is a tamper-evident, reverified host-side store. It is **not** being claimed as an immutable CAS:
a same-owner process with sufficient filesystem access, or a privileged process, can still alter
permissions or storage state. The remaining filesystem and service-boundary hardening is listed
below.

### Deterministic artifact analysis

The first artifact-bound detector now:

- derives npm lifecycle, chained-command, `main`, extensionless, and explicit or implicit
  `node-gyp` trigger surfaces;
- derives wheel and sdist import, entry-point, build-backend, metadata-inline, and native/external
  trigger surfaces;
- follows bounded local JavaScript and Python edges, including Python relative imports and valid
  sdist backend-path sibling imports;
- emits artifact- and manifest-bound findings with stable file ids, validated ranges, selected-byte
  digests, trigger context, confidence, and limitations;
- applies bounded work limits for text bytes, trigger surfaces, graph edges, import attempts,
  command candidates, reachable files, and total analyzed text;
- marks dynamic, external, unsupported, truncated, or otherwise unresolved coverage as incomplete
  instead of turning absence of a lexical match into a clean result; and
- produces deterministic JSON plus an analysis digest for evidence-job binding.

This analyzer is intentionally not described as AST-complete. Its rules are lexical and graph
heuristics, so comments and strings can create false positives and dynamic language behavior can
remain unresolved. A bounded no-finding result requires revalidation against the normalized
artifact, but it has no allow authority.

### Evidence subject and structural validation

`ArtifactEvidenceSubjectV2` binds the original artifact digest, acquisition-envelope digest,
manifest digest, and quarantine object key. `EvidenceEnvelopeV2` checks exact subject, policy,
producer, job, job-spec, timing, limitation, and replay-snapshot structure. Completeness is a
separate typestate from structural validity.

The API states the trust boundary directly: structurally validated evidence is unauthenticated and
cannot authorize allow. Authority and final verdict construction remain outside this observation
record.

## Manifest schema version 2

The artifact manifest and its canonical serialization were advanced to version 2 because npm's
declared `main` target became part of the normalized artifact contract. That field affects trigger
discovery and therefore the meaning of the manifest digest; keeping the version-1 schema would have
allowed two materially different analysis surfaces to share an old schema interpretation.

Version 2 is therefore a semantic identity change, not a cosmetic rename. Stored version-1
manifest digests must not be silently interpreted as version-2 manifests or reused as evidence for
the new trigger graph.

## Verification recorded so far

The latest focused runs known at this checkpoint were:

| Area | Result | What it exercised |
| --- | ---: | --- |
| Artifact crate | 18 passed | envelope validation, normalization, canonical vectors, hostile archive forms |
| Quarantine/cache crate | 26 passed | bounded ingest, publication races, restart/reopen, mutation, substitution, link and permission checks |
| Detector crate | 29 passed | npm/wheel/sdist trigger graphs, findings, coverage, and adversarial resource bounds |
| Evidence crate | 15 passed | legacy evidence plus v2 subject, structure, completeness, timing, mismatch, and replay-snapshot checks |
| Runner crate | 12 passed | CAS-to-envelope-to-manifest binding, substitution rejection, parser preflight, restart, detector/evidence composition, and host-probe refusal |
| Focused CLI package-risk tests | 32 passed | explicit workspace subject semantics and rejection of legacy pseudo-artifact-hash history |

The repository-wide landing pass also completed on this tree:

| Check | Result |
| --- | ---: |
| Rust workspace tests, all targets | 598 passed; 0 failed |
| Rust formatting | Passed |
| Rust workspace Clippy, warnings denied | Passed |
| Rust documentation, warnings denied | Passed |
| Swift helper tests | 14 passed; 0 failed |
| Swift helper build | Passed |
| Package-risk, scanner-integration, and synthetic attack smoke scripts | Passed |
| Restricted-lab harness self-test using synthetic metadata only | Passed |
| Guest project-payload and timeout C harnesses | Passed |
| Offline source-fixture corpus | Passed with zero failures; reports remained in a temporary directory |
| Tracked shell syntax | Passed with `bash -n` |

These checks are not the final Phase 1 or Phase 2 qualification. Parser fuzz/property
qualification and the benign-control gate remain open.

No result in this table is a malware detection result. The July 1 restricted campaign remains at
7/11 behavior-related detections under its documented scoring rules, with four generic safe blocks.

## Explicitly open blockers

### Evidence authentication and admission

- Define a strict canonical wire format and bounded decoder for evidence rather than relying on
  in-process Rust structure alone.
- Authenticate provenance with signatures or an equivalently reviewed channel, including key id,
  issuer, freshness, expiry, revocation, and supersession semantics.
- Replace the advisory replay snapshot with atomic reserve/accept replay protection.
- Keep evidence observation-only until a trusted admission layer validates authenticated evidence
  and constructs a separately authoritative `VerdictEnvelope`.

### Guest transport and AN-108

- Stream exact bytes into a fresh guest through a bounded artifact channel.
- Rehash inside the guest before any package-controlled code runs.
- Return an authenticated receipt binding artifact digest, byte length, scenario, guest image,
  runner, and transport session.
- Prove that the analyzed bytes and executed bytes are identical under substitution, truncation,
  replay, restart, and transport-failure tests.

Until this exists, the implementation is a verified host-side source for transport; it does not
satisfy AN-108's scanned-bytes-equal-detonated-bytes exit criterion.

### Quarantine service and filesystem hardening

- Move critical path traversal and object access to reviewed descriptor-relative/openat-style
  operations so intermediate-path replacement cannot redirect access.
- Define and verify ACL and extended-attribute policy, not only POSIX ownership and mode.
- Add aggregate store quotas and reservation accounting in addition to per-object bounds.
- Scavenge stale incoming objects safely and add a store-generation/format marker for recovery and
  migrations.
- Put the store behind a least-privilege service boundary if other same-user processes must be
  treated as hostile.

These gaps are why this checkpoint uses “sealed and reverified” rather than “immutable.”

### Static-analysis quality and benign gates

- Select reviewed JavaScript/TypeScript, Python, shell, and package-metadata parsers through the
  Phase 2 ADR and replace security-critical lexical approximations with validated AST/data-flow
  analysis where practical.
- Complete language, dynamic-import, native, build-backend, and dependency-closure accounting.
- Add version-diff analysis and normalized output from the existing scanner set.
- Run clean lifecycle/build-hook controls and the planned balanced benign cohort before making any
  false-positive, usability, or observed-clean claim.

### Later phases remain untouched

This checkpoint does not implement or qualify:

- artifact-specific AI review v2, its coverage manifest, multi-pass analysis, prompt-injection
  defenses, or provider reproducibility contract;
- typed npm, wheel, and sdist VM detonation scenarios;
- an unprivileged package user, complete descendant teardown, or fresh-per-scenario VM lifecycle;
- protected process, file/canary, DNS, connection, and HTTP(S) telemetry;
- authenticated dynamic evidence, verdict fusion, or admission;
- the four-miss, full eleven-sample, benign, or held-out evaluation gates; or
- Cloudflare, AWS Lambda MicroVM, or self-hosted Firecracker execution.

Cloud evaluation remains downstream of a correct, evidence-backed local implementation.

## Recommended next sequence

1. Finish the repository-wide verification pass and land this checkpoint without weakening parser,
   coverage, or no-host-execution failures.
2. Close the evidence trust boundary: strict wire decoding, authenticated provenance, and atomic
   replay acceptance.
3. Implement guest-side digest verification and an authenticated transport receipt, then exercise
   AN-108 substitution and failure cases with inert artifacts.
4. Complete Phase 2 with reviewed parsers, version comparison, scanner composition, and a measured
   benign baseline.
5. Build artifact-specific AI review v2 on the exact artifact/file/range contracts.
6. Compile typed detonation scenarios and protected telemetry only after the artifact and evidence
   identities are stable.
7. Keep all restricted real-malware gates closed until inert scenario, telemetry, evidence, and
   benign qualification gates pass and the separate lab workflow is explicitly approved.

## Claim boundary

The supportable statement at this checkpoint is:

> WhoaThere has an inert exact-artifact normalization and deterministic-analysis spine with
> host-side quarantine revalidation and structurally bound, non-authoritative evidence.

The following statements are not yet supportable:

- “The quarantined CAS is immutable.”
- “The bytes analyzed are proven to be the bytes detonated.”
- “The evidence is authenticated or can authorize installation.”
- “The detector catches arbitrary malicious npm or PyPI packages.”
- “The four previous misses are fixed.”
- “The known corpus detects 11/11.”
- “Benign false-positive or developer-friction gates pass.”
- “Dynamic process, file, or network behavior is independently observed.”
