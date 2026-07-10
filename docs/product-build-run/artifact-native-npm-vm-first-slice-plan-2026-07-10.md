# Artifact-Native npm VM First-Slice Plan

Date: 2026-07-10

Status: implementation plan based on a read-only `AN-400` through `AN-409` survey; documentation
only; no VM execution or malware handling was performed

## Relationship To The Canonical Work

This is the implementation plan for the first macOS VM slice of Phase 4 in the
[canonical artifact-native detection execution plan](artifact-native-detection-execution-plan.md).
It is subordinate to that plan and to the
[authoritative threat model](../outputs/GOAL-01/threat-model.md), as narrowed by the
[artifact-native threat-model addendum](artifact-native-threat-model-addendum.md).

The exact-byte host spine already delivered is described in the
[Phase 1 and static-analysis checkpoint](artifact-native-phase1-static-checkpoint-2026-07-09.md).
The following checkpoints constrain the evidence and runtime design, but do not themselves provide
VM or package-execution evidence:

- [Artifact Review v2 local runtime checkpoint](artifact-review-v2-local-runtime-checkpoint-2026-07-09.md)
- [Artifact Review v2 authenticated-evidence checkpoint](artifact-review-v2-authenticated-evidence-checkpoint-2026-07-09.md)
- [Artifact Review v2 replay and lineage authority ADR](artifact-review-v2-authority-store-adr-2026-07-09.md)

This plan does not supersede the July 1 result. Containment held, but the known-malware behavior
gate remains 7/11. Nothing in this document is a new detection, benign-friction, admission, or
release-readiness claim.

## Decision Summary

Build a new artifact-native VM path for one dependency-free inert npm tarball before generalizing
to dependency closures, wheels, or sdists. The path will:

1. compile the already validated `ArtifactManifest` into typed scenarios in Rust;
2. reopen the exact quarantine object and stream the original bytes through a bounded binary
   channel;
3. run each scenario in its own writable APFS clone of a stopped, measured macOS base;
4. configure the scenario VM with no network device;
5. rehash the exact tarball in the guest before any package-controlled code runs;
6. have a root-owned guest supervisor launch npm and all package code under a dedicated
   unprivileged UID;
7. terminate and account for the complete process and listener set before stopping the VM;
8. destroy the clone whether execution succeeds, fails, times out, or loses evidence; and
9. return bounded scenario evidence, never a guest verdict and never files for sync-back.

The existing `whoathere vm detonate` flow is retained for its documented local project/fixture
preview scope. It is not the transport, protocol, runner, evidence source, or CLI for this slice.

## Why The Existing Detonation Path Cannot Be Reused As-Is

The current implementation has useful VM machinery, but its execution semantics do not satisfy the
artifact-native threat model. These are current code facts, not hypothetical future risks.

| Current fact | Why it is disqualifying for `AN-400` through `AN-409` |
| --- | --- |
| `whoathere-guest-ready` is installed as a root-owned LaunchDaemon and its package child does not drop UID or groups | npm, pip, uv, lifecycle code, and child processes currently inherit root in the guest. `AN-407` requires a root runner above an unprivileged package user. |
| `run_shell_fixture` executes `/bin/sh -c <command>` | The control path is stringly typed, and a shell is part of the runner rather than only an unavoidable implementation detail of npm lifecycle semantics. The new compiler must emit enums and fixed argv templates, not package-controlled shell strings. |
| Timeout handling calls `kill(pid, SIGKILL)` and waits only for that leader | There is no dedicated session, complete descendant accounting, escaped-child handling, listener scan, or post-run quiescence proof. Background or reparented work can outlive the nominal command. |
| The installed VM uses the writable persistent `bundle/disk.img` | Jobs can leave state for later jobs. The helper does not currently create and destroy one fresh disk namespace per artifact/scenario. |
| The shared macOS configuration always attaches `VZNATNetworkDeviceAttachment` | Direct NAT is neither default-deny nor an independently trustworthy observation path. The first slice requires an empty network-device list, with no NAT fallback. |
| The guest derives `canary_access_detected`, `network_attempt_detected`, and `filesystem_write_detected` from package-visible marker files | Package code can create, omit, remove, or imitate those markers. Marker booleans are useful fixture test oracles but are not protected behavioral evidence. |
| The guest returns JSON containing a `verdict`, including `allow_observed_clean`, over the existing VSOCK session | Request nonce and context comparisons detect accidental mismatch, but there is no protected sensor provenance or cryptographic evidence authority. The execution plane must emit observations and limitations, not authority. |
| The legacy request and response schemas contain `sync_back_enabled`, and project mode can return a guest-produced archive | Existing Rust scope checks are useful defense in depth, but an artifact protocol must have no sync request, output archive, or copy-back operation at all. |
| The legacy helper consumes synthesized fixtures or a bounded hex-encoded project mirror | It neither receives an exact CAS-backed npm tgz nor proves that the guest installed the same bytes analyzed on the host. |
| A running VM and its VSOCK broker serve multiple detonation requests | A successful cleanup claim cannot substitute for the stronger rule that a contaminated environment is never used for the next scenario. |

These limitations do not invalidate the narrower historical `vm detonate` claims. They mean that
adding an artifact digest field to that protocol would not complete Phase 4.
For the artifact-native adversary model, the current dynamic result is marker-only and
unauthenticated; nonce matching does not change that authority boundary.

Survey source anchors are the current
[guest agent](../../whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c),
[Swift VM helper](../../whoathere/helpers/macos-vm-helper/Sources/WhoaThereMacosVmHelper/main.swift),
[Swift option parser](../../whoathere/helpers/macos-vm-helper/Sources/WhoaThereMacosVmHelperCore/HelperCore.swift),
[Rust macOS VM policy](../../whoathere/crates/whoathere-macos-vm/src/lib.rs), and
[legacy fixture detonation crate](../../whoathere/crates/whoathere-detonation/src/lib.rs).

## Reusable Foundations

The new path should reuse code only where its guarantee matches the new boundary.

### Rust foundations

- `whoathere-artifact` already provides exact `ArtifactEnvelope` and `ArtifactManifest` bindings,
  safe npm tgz normalization, canonical and noncanonical root handling, lifecycle scripts, `main`,
  exports, bins, dependency declarations, native markers, completeness, and a 64 MiB original-byte
  ceiling.
- `PreparedArtifact` in `whoathere-runner` retains the opaque quarantine handle. Its
  `verified_transport_source` method reopens, bounds, and rehashes that exact object into a
  `VerifiedArtifactLease`; it does not re-resolve a registry coordinate.
- The quarantine CAS already gives the host a digest- and length-checked source snapshot. Its
  same-user and service-boundary limitations remain explicit.
- `DetonationJobScope` and `decide_detonation_sync_back` in `whoathere-macos-vm` already prove that
  artifact, unknown-artifact, and restricted-lab scopes cannot produce the legacy helper's
  `--sync-back` argument. Keep those tests as defense in depth.
- The Artifact Review v2 runtime demonstrates useful patterns: construct all inputs before launch,
  bind execution before it starts, use strict bounds, preserve positive prefixes on failure, keep
  completion separate from safety, and prove cleanup rather than relying on `Drop`.
- The Artifact Review v2 authentication slice demonstrates challenge-before-execution, strict
  canonical reconstruction, signature verification, replay/lineage transitions, and honest
  authority receipts. Its schema is review-specific and must not be relabeled as VM evidence.

### macOS VM foundations

- The signed Swift helper already owns Virtualization.framework configuration, macOS image
  installation, VM start/stop, health checks, VSOCK, helper packaging, and base-image metadata.
- The VSOCK listener and request/result broker establish a working host/guest control route.
- Offline guest provisioning can install root-owned Node/npm and Python toolchains with receipts.
  The new image receipt must additionally bind the exact Node executable and npm CLI bytes used by
  the typed runner.
- Swift parser tests, helper build tests, C guest harnesses, and cloud-Mac validation scripts provide
  useful test infrastructure. They must exercise the new protocol separately from legacy fixture
  behavior.

## First-Slice Scope

The first executable subject is one inert npm `.tgz` that is already in the quarantine CAS and has
successfully completed safe normalization.

The executable adapter remains guarded by an `InertQualificationOnly` policy whose allowed fixture
digest comes from a repository test-fixture build receipt, not a CLI-supplied label or package
metadata. A different digest fails before the helper. Removing that guard is a separately reviewed
product-enablement change after the inert gates pass; corpus labels never become detections.

The compiler accepts the tarball only when all of the following are true:

- the envelope and manifest validate and bind the same original SHA-256 and byte length;
- `magic_detected_format == npm_tar_gzip`;
- normalization is `complete`;
- package identity and npm metadata are present;
- all dependency-declaration groups are empty, including optional, peer, bundled, and bundle
  declarations;
- `requires_offline_closure == false`;
- `implicit_node_gyp_rebuild == false` and the native-binary inventory is empty;
- the exact CAS object can be reopened as a verified lease; and
- the artifact is at most the existing 64 MiB normalization ceiling.

Rejecting dependency-bearing or native packages in this slice is an explicit unsupported result,
not a malicious detection. `AN-405` remains open until a separately acquired, provenance-bound
offline closure exists.

The initial compiler emits two install scenarios, in deterministic order:

1. exact local-tarball install with `CI=false`; and
2. exact local-tarball install with `CI=true`.

Each scenario gets a distinct job, evidence identity, challenge, clone, boot, canary set, package
home, process session, evidence record, and destruction record. There is no same-VM second scenario.
The npm version is fixed by the measured base-image profile. The initial trigger target is npm's
normal local-tarball install lifecycle, including declared `preinstall`, `install`, and
`postinstall` behavior and any other hook only after a conformance fixture proves it applies to the
pinned npm version and exact tarball workflow.

Main/export loading and bounded bin probes should be modeled now as separate scenario variants but
remain disabled in this first landing. They require their own argument policy and fresh clones;
they must not be appended as free-form commands to the install scenario.

### `AN-400` through `AN-409` coverage

| Work package | First-slice disposition |
| --- | --- |
| `AN-400` scenario compiler | Implement the backend-neutral typed npm compiler and canonical plan/spec bindings. |
| `AN-401` artifact transport | Implement the raw bounded Rust-to-helper-to-guest stream and guest pre/post rehash. |
| `AN-402` npm consumer workflow | Implement exact local-tgz install and lifecycle execution only; defer main/export/bin probes. |
| `AN-403` wheel workflow | Deferred; the types must not pretend npm coverage applies to wheels. |
| `AN-404` sdist workflow | Deferred; no build or derived-wheel claim is made. |
| `AN-405` dependency closure | Support only a canonically bound empty closure; reject every nonempty closure. |
| `AN-406` scenario matrix | Implement `CI=false` and `CI=true` as separate clones; defer other matrices. |
| `AN-407` guest privilege split | Implement a root-owned supervisor and fixed unprivileged package UID/GID. |
| `AN-408` no-sync enforcement | Omit sync from every new type, command, protocol, and return channel. |
| `AN-409` complete teardown | Implement session/group control, descendant and listener accounting, VM stop, and verified clone destruction. |

This table is a scope ledger, not a completion claim. Each row remains open until its acceptance
evidence below passes.

## Rust Contract And Landing Plan

### Contract ownership

Add the typed compiler and canonical request wire under
`whoathere/crates/whoathere-detonation/`, split from its current fixture-only `lib.rs`:

```text
whoathere-detonation/src/
  artifact.rs              artifact scenario domain and validation
  npm.rs                   npm compiler and fixed workflow profiles
  wire.rs                  closed canonical helper-submission projection
  lib.rs                   exports; legacy fixture module remains explicit
```

Add dynamic observation types under `whoathere-evidence`, the Mac adapter under
`whoathere-macos-vm`, and orchestration beside the existing exact-artifact preparation path:

```text
whoathere-evidence/src/artifact_dynamic_v1.rs
whoathere-sandbox/src/artifact_backend_v1.rs
whoathere-macos-vm/src/artifact_backend.rs
whoathere-runner/src/artifact_dynamic.rs
whoathere-cli/src/artifact_inspect.rs
```

The CLI module parses and renders only. It must not acquire dependencies, interpret package
metadata, construct npm commands, handle VM disk paths, or decide a verdict.

### Compiler inputs

The implementation names may change before merge, but the following closed concepts are required:

```rust
pub struct ArtifactScenarioCompilationRequestV1<'a> {
    pub envelope: &'a ArtifactEnvelope,
    pub manifest: &'a ArtifactManifest,
    pub subject: &'a ArtifactEvidenceSubjectV2,
    pub policy: &'a ArtifactScenarioPolicyV1,
}

pub enum DependencyClosureV1 {
    Empty {
        declaration_set_sha256: Sha256Digest,
    },
    // A nonempty, digest-bound form is a later AN-405 change.
}

pub enum NpmEnvironmentProfileV1 {
    CiFalse,
    CiTrue,
}

pub enum ArtifactScenarioKindV1 {
    NpmLocalTarballInstall {
        environment: NpmEnvironmentProfileV1,
    },
    NpmMainOrExportProbe, // modeled but rejected by first-slice policy
    NpmBinProbe,          // modeled but rejected by first-slice policy
}
```

`ArtifactScenarioPolicyV1` is trusted policy data. It fixes permitted artifact forms, npm runtime
requirements, scenario kinds, time/resource ceilings, required evidence classes, no-network
posture, freshness, teardown requirements, and schema versions. Package bytes cannot select or
relax it.

The compiler output is backend-neutral. `BackendCapabilitiesV1` and `BackendLifecycleV1` belong in
`whoathere-sandbox`. The Mac adapter in `whoathere-macos-vm` capability-matches that output, then
constructs `MacosArtifactRunSpecV1` by adding the selected base-image, helper, guest-supervisor,
Node, npm, clone, and protocol identities. This dependency direction prevents the domain compiler
from depending on the Mac backend or introducing a crate cycle.

### Compiled scenario

One backend-neutral `ArtifactScenarioTemplateV1` represents exactly one environment and one
scenario. Its canonical form includes:

- schema and compiler versions;
- job, run, evidence, and scenario ids supplied by the trusted orchestrator;
- artifact, acquisition-envelope, manifest, CAS-object, and empty-closure digests;
- package identity;
- scenario kind and environment profile;
- declared lifecycle hook enum values and command-text digests for coverage accounting only;
- required OS/architecture, runtime profile, isolation, transport, telemetry, and lifecycle
  capabilities;
- exact artifact length and transport ceiling;
- wall-clock, output, process, file, and descriptor ceilings;
- required process, privilege, transport, cleanup, listener, clone-destruction, and sensor-health
  evidence classes; and
- explicit `NoNetworkDevice` and `DestroyClone` enum values.

After capability matching, `MacosArtifactRunSpecV1` adds measured base-image, helper,
guest-supervisor, runner, Node, npm, clone-policy, and protocol digests without weakening any
template requirement. The final run spec represents one helper invocation, one clone, and one
scenario.

Neither contract contains a registry coordinate to resolve, filesystem path, npm script command
string, shell command, arbitrary argv, output-copy instruction, or sync field.
`#[serde(deny_unknown_fields)]` applies to every wire object. Canonical serialization and separate
domain-separated template, run-spec, and ordered-plan SHA-256 values are part of the contract.

The lifecycle command text remains bound indirectly by the manifest and directly by a digest, but
the compiler never executes that text. npm will interpret scripts from the exact installed tarball
as part of the intentionally untrusted package semantics inside the VM.

### Compiler behavior

`compile_artifact_scenarios_v1` must:

1. revalidate the envelope, manifest, subject, canonical digests, and exact format relationship;
2. reject incomplete normalization or any first-slice policy mismatch;
3. prove the dependency declaration set is empty and construct `DependencyClosureV1::Empty`;
4. derive hook coverage from typed npm metadata, not by reparsing package text;
5. emit the `CI=false` and `CI=true` scenario templates in canonical order;
6. calculate each canonical template digest and the ordered plan digest; and
7. return typed unsupported or invalid-input errors without launching the helper.

No generic failure counts as trigger coverage. Tests must assert the intended lifecycle hook was
reached under the pinned npm runtime.

### Orchestration and CLI

The provisional primary command is:

```text
whoathere artifact inspect --file <package.tgz> --ecosystem npm --dynamic \
  --backend macos-local [--json]
```

This is a new artifact workflow, not an alias for:

```text
whoathere vm detonate ...
```

For the first slice, only local inert fixtures satisfying the dependency-free policy are permitted
through the executable qualification path. Coordinate acquisition and general untrusted-package
availability remain later `AN-700` work.

The new command has no `--sync-back`, generic `--execute <tool> -- <args>`, project workspace,
project payload, or fixture selector. Supplying `--sync-back` is a parse error before a helper is
selected. Machine output reports stage status and evidence posture; it does not use `allow`,
`observed_clean`, or a guest verdict.

`whoathere-runner` performs this sequence:

1. obtain `PreparedArtifact` from the existing CAS/envelope/normalization path;
2. compile the scenario plan;
3. issue the pre-execution evidence challenge and identities;
4. reopen `PreparedArtifact::verified_transport_source` for each scenario;
5. stream one Mac run spec plus those lease bytes to one helper invocation;
6. strictly validate returned evidence and preserve every positive observation on partial failure;
7. independently aggregate scenario completion without making an admission decision; and
8. discard the lease and all bounded transient buffers.

## Exact Host-To-Guest Transport

### CLI to Swift helper

Do not put artifact bytes in argv, JSON hex, a project tar mirror, or a helper-visible arbitrary
host path. The Rust process writes one bounded binary submission to the helper's stdin:

```text
magic[8] | version:u16 | frame_type:u16 | header_len:u32 |
artifact_len:u64 | artifact_sha256[32] | canonical_header | artifact_bytes
```

All integer fields use network byte order. The initial limits are 256 KiB for the canonical header,
64 MiB for the artifact, and no trailing bytes. The header binds the complete run-spec digest,
challenge/execution identity, and artifact length/digest. The helper incrementally hashes the
payload while reading it and refuses short input, extra input, digest mismatch, duplicate frame,
unknown version/type, or allocation pressure. It need not hold a second artifact copy.

The Swift implementation belongs in separate files, not another large block in `main.swift`:

```text
Sources/WhoaThereMacosVmHelper/
  ArtifactRunCommand.swift
  ArtifactRunProtocol.swift
  DisposableArtifactVM.swift
  ArtifactGuestChannel.swift
```

`HelperCore.swift` gains a distinct `.artifactRun` command with only state/base selection and
execution authorization. Its option type has no sync property.

### Swift helper to guest supervisor

Use a new VSOCK port and protocol, for example `whoathere.artifact_scenario.v1`; do not extend
`whoathere.guest_detonation.v1`. The same length, digest, version, EOF, and trailing-data rules apply
on this hop. Control messages are closed, bounded canonical JSON; the artifact is a raw byte frame,
not base64 or hex.

The host helper records:

- the exact digest and length it received from Rust;
- the exact digest and length it sent on VSOCK;
- the run spec, challenge, VSOCK session, base-image, clone, helper, and guest-supervisor identities;
- whether every byte and the expected EOF were observed; and
- any transport failure before returning evidence.

### Guest staging and rehash

The root supervisor creates an exclusive root-owned per-scenario directory with no symlink-following
operations, writes the tarball with `O_CREAT | O_EXCL | O_NOFOLLOW`, and enforces the 64 MiB limit
while streaming. It must:

1. hash and count bytes while writing;
2. `fsync` and close the file;
3. reopen without following links, verify regular-file identity, length, and SHA-256;
4. make the root-owned file read-only to the package UID while keeping its parent non-writable;
5. verify the same inode, length, and digest immediately before npm launch;
6. verify them again after npm exits or is terminated; and
7. bind all three guest observations to the scenario evidence.

No unpacking or package-controlled code may occur before the pre-launch rehash succeeds. npm
installs only this local path. Registry re-resolution of the target is absent from the protocol and
command.

## Disposable macOS VM Lifecycle

### Measured base

Maintain a stopped, trusted base VM that contains only the reviewed guest supervisor and pinned
toolchain. Its authenticated build receipt binds at least the base generation, disk and auxiliary
storage identities, macOS build, hardware model, guest supervisor, Node executable, npm CLI,
runner configuration, and provisioning receipt.

The current image manifest alone is not sufficient after in-place guest provisioning. Qualification
must create a post-provisioning base measurement and prevent the base from being launched writable
as a scenario VM. Per-run source-file identity checks and protected ownership are required; the
first cloud-Mac campaign also rehashes the full base before and after the campaign. Any stronger
per-run measurement optimization needs its own reviewed authority.

### One APFS clone per scenario

Before each scenario, with the base stopped and locked against concurrent mutation, the helper:

1. creates a random, mode-`0700` run directory under a dedicated artifact-run root;
2. uses APFS copy-on-write clone operations for the base disk and required auxiliary storage;
3. fails closed if the filesystem or clone operation cannot prove copy-on-write cloning; there is
   no silent fallback to the persistent base disk or legacy bundle;
4. copies only the bounded, measured VM metadata needed to boot and records every digest;
5. attaches only the writable clone, never the base disk; and
6. creates canaries and scenario state only after the clone is unique.

The clone is not reused for another scenario, even when the first scenario looks clean.

APFS clone deletion is namespace destruction, not a claim of forensic secure erasure from physical
media. Raw disks and restricted traces remain outside git and follow the restricted storage policy.

### No-NIC configuration

Add a separate `buildArtifactScenarioConfiguration` path. It shares the reviewed macOS platform,
storage, graphics, and VSOCK setup but sets:

```swift
configuration.networkDevices = []
```

It must never call the legacy builder that attaches `VZNATNetworkDeviceAttachment`. If a supported
macOS guest cannot boot or npm cannot complete the inert local-tarball workflow with no NIC, the
slice fails; NAT is not an allowed fallback.

The guest additionally runs npm in offline mode with audit, funding, update checks, and lockfile
mutation disabled and with a fixed invalid registry configuration. These are defense in depth. The
empty network-device list is the primary first-slice egress control.

No NIC proves that this scenario had no VM network attachment. It does not prove that network intent
was absent or observed. Network evidence remains explicitly unavailable until the controlled
host-visible topology in Phase 5 exists.

### Stop and destruction

On every terminal path, the helper stops the VM with a bounded escalation, verifies that the VZ VM
is stopped and its channel is closed, closes all clone descriptors, removes the complete run
directory, and verifies that the owned path is absent. A primary execution or evidence failure is
preserved if cleanup also fails. Clone destruction failure is a separate terminal error and makes
the evidence incomplete.

## Guest Privilege And Runner Design

Provision a dedicated package account in the base image, with its numeric UID/GID recorded in the
base receipt. It must not be UID 0, an administrator, a member of privileged groups, or the owner of
the supervisor, toolchain, protocol configuration, artifact staging parent, or evidence channel.

Install a separate root-owned supervisor rather than adding artifact execution to
`whoathere-guest-ready.c`:

```text
/usr/local/libexec/whoathere-artifact-supervisor
/Library/LaunchDaemons/com.whoathere.artifact-supervisor.plist
```

The supervisor remains root only to own the protected control channel, staging, process accounting,
UID transition, and teardown. It is single-purpose and receives no project mirror or sync request.

For package execution, the supervisor:

- creates a fresh consumer directory, fixed minimal consumer `package.json`, `HOME`, `TMPDIR`, npm
  cache, and logs owned by the package UID, binding the consumer-template digest in the run spec;
- creates fake canaries only after clone uniqueness and exposes no host credential or home path;
- uses a reviewed single-threaded launch boundary that clears supplementary groups, sets the fixed
  GID and UID, applies resource limits, closes all unlisted descriptors, and `execve`s a fixed
  absolute Node executable with the fixed measured npm CLI and typed argv;
- records and independently checks that the package process credentials are the expected nonzero
  UID/GID before accepting start evidence; and
- never gives the package UID write access to the supervisor, staged tgz, base toolchain, VSOCK
  control state, or evidence material.

The fixed first-slice command template is semantically equivalent to:

```text
<measured-node> <measured-npm-cli> install <root-owned-exact-tgz> \
  --offline --foreground-scripts --ignore-scripts=false \
  --no-audit --no-fund --package-lock=false
```

The actual argv is built from constants and typed values. It is not passed through `/bin/sh -c`.
npm may itself use a shell for package-declared lifecycle scripts; that is the package behavior the
scenario intentionally exercises, under the unprivileged UID inside the disposable VM.

## Descendant, Daemon, And Listener Cleanup

A process group alone is insufficient because package code can daemonize, reparent, or call
`setsid`. The first-slice supervisor therefore combines several controls:

1. capture a protected pre-scenario process and listener baseline after boot;
2. launch npm as a new session/process-group leader and retain the unreaped leader as an identity
   anchor during cleanup;
3. record process start/exit and ancestry where the selected guest sensor can do so without package
   write access;
4. on normal exit, timeout, cancellation, or protocol error, close inputs, send `SIGTERM` to the
   group, wait a bounded grace period, then send `SIGKILL`;
5. enumerate the complete process table and terminate every remaining package-UID process plus every
   recorded descendant, including reparented or escaped-session children;
6. enumerate TCP and UDP listeners through a root-owned, bounded kernel interface and compare them
   with the pre-scenario baseline;
7. require zero unexpected process or listener after cleanup and record dropped-event or enumeration
   failures; and
8. stop the VM and destroy the clone regardless of quiescence outcome.

Unexpected survivors, unqueryable processes, sensor gaps, PID ambiguity, listener-enumeration gaps,
or failed signals make teardown evidence incomplete. They must not be rewritten as a clean run.

The unique-clone rule is the final cross-scenario isolation control: even a failed quiescence proof
never permits another scenario to run in that VM. Phase 5 must still add host-visible or otherwise
independently protected telemetry before descendant and listener observations can support a broad
detection claim against a guest-compromise adversary.

## Structural Absence Of Sync-Back

For artifact-native jobs, no-sync is a type and protocol property, not a boolean expected to be
false.

- `ArtifactScenarioTemplateV1` and `MacosArtifactRunSpecV1` have no sync or output-copy field.
- The `artifact-run` Swift options have no `detonationSyncBack` property and accept no `--sync-back`
  token.
- `whoathere.artifact_scenario.v1` has no sync request, sync response, output archive, host target,
  or guest-file frame type.
- The guest supervisor cannot construct an archive for the host.
- The helper accepts only bounded evidence on the return channel.
- The CLI grammar rejects `--sync-back` for `artifact inspect` before helper launch.
- The Rust backend adapter does not implement or call the legacy project sync code.
- Admission, if added later, must independently reacquire digest-matched inert bytes; it never trusts
  files from this clone.

Keep the existing scope-based sync denial tests, then add negative compilation, parser, protocol,
and end-to-end tests proving that no artifact scenario reaches the legacy sync implementation.

## Evidence, Not Verdict

The guest supervisor reports events, coverage, limitations, and terminal state. It does not emit
`allow`, `deny`, `malicious`, `observed_clean`, or a confidence score.

`ArtifactScenarioEvidenceV1` binds at least:

- the complete evidence subject, template, run-spec, scenario, empty-closure, policy, and challenge
  identities;
- helper, base image, clone, guest supervisor, runner, Node, npm, and protocol identities;
- host-received, host-sent, guest-written, guest-prelaunch, and guest-postrun artifact digests and
  lengths;
- transport EOF, bounds, replay, and error state;
- scenario kind, environment profile, fixed command-template identity, package UID/GID, timestamps,
  exit, timeout, and cancellation state;
- process ancestry, survivor, reparenting, listener, forced-kill, and quiescence observations;
- no-NIC configuration evidence and an explicit `network_intent_not_observed` limitation;
- sensor heartbeat, dropped-event count, and per-class coverage state;
- bounded stdout/stderr digests, with raw material restricted and never included in normal output;
- VM stop, channel close, clone deletion, and cleanup completeness; and
- evidence provenance, key id, creation/expiry, replay acceptance, durability posture, and
  rollback-protection posture.

Every observation has a source posture. Host-observed clone and VZ configuration facts are distinct
from root-guest observations and package-produced fixture output. Package-visible markers may be
used in inert harness assertions but are excluded from product behavioral findings.

The trusted verifier reconstructs the expected subject, template, and run spec, validates every
closed enum and digest, preserves positive observations from partial runs, and keeps completion
separate from provenance. Missing required telemetry, failed rehash, timeout, cleanup uncertainty,
or destruction failure yields incomplete evidence.

The Artifact Review v2 signature implementation should be generalized only through a reviewed
shared canonical-signature/authority layer. VM evidence must not call an Artifact Review wrapper or
claim that AI-review authentication proves guest observations. The same challenge-before-execution,
strict expected-body reconstruction, freshness, replay reservation, and monotonic-positive rules do
apply.

During local development, a MemoryOnly authority receipt remains explicitly
`NoRestartOrRollbackProtection`. It is useful for deterministic tests but does not close `AN-506`.
Protected Mac authority work remains required before authenticated VM evidence can affect admission.
Regardless of authority posture, this slice returns `can_authorize_allow() == false`.

## Implementation Sequence

### Landing 1: Rust types and compiler

- Add the closed scenario, policy, empty-closure, plan, and helper-wire types.
- Implement dependency-free npm validation and deterministic `CI=false`/`CI=true` compilation.
- Add canonical vectors and template/plan digests.
- Add the new CLI grammar and dry, nonexecuting render path.
- Keep the helper uncallable until the later landings pass.

### Landing 2: Binary transport and disposable helper path

- Add the new stdin and VSOCK frame codecs with strict bounds.
- Add the separate Swift `artifact-run` command.
- Add stopped-base locking, APFS disk/auxiliary clones, no-NIC configuration, and unconditional
  teardown.
- Return only transport/lifecycle evidence; do not launch npm yet.

### Landing 3: Guest supervisor and unprivileged npm

- Provision the package account and separate root supervisor.
- Add root-owned exact-byte staging and three guest rehash points.
- Add fixed-argv npm execution under the package UID.
- Add process/session/UID/resource/descriptor controls and complete teardown accounting.

### Landing 4: Evidence reconstruction and orchestration

- Add the strict dynamic evidence schema and verifier.
- Bind the helper run to a pre-execution challenge and authority posture.
- Orchestrate one helper/clone per compiled scenario.
- Render stage status, observations, and limitations without a verdict.

### Landing 5: Inert local and cloud-Mac qualification

- Pass all deterministic, protocol, helper, guest, and end-to-end tests locally.
- Run the inert-only second-host campaign below.
- Publish a sanitized checkpoint with exact versions, test counts, limitations, and open gates.

No landing enables real-malware execution.

## Verification Matrix

### Rust compiler and contract tests

- canonical and noncanonical dependency-free npm tgz manifests compile to exactly two ordered
  scenarios;
- any byte, envelope, manifest, CAS object, policy, runtime, profile, or hook change changes the
  appropriate template, run-spec, or plan digest;
- wrong format, missing identity, incomplete normalization, dependency declaration, bundled
  dependency, native member, implicit node-gyp, bad digest, or oversized artifact fails before the
  helper;
- canonical wire rejects unknown fields, duplicate fields, invalid enums, invalid digests, malformed
  lengths, and noncanonical bytes;
- the canonical template and run spec contain no script command, shell string, host path, registry
  fallback, sync field, or arbitrary argv;
- `artifact inspect --sync-back` and generic tool argv are parser errors;
- legacy `vm detonate` behavior remains covered but is not called by the artifact backend.

### Transport tests

- zero-length input is rejected, while valid small inputs and the exact 64-MiB ceiling stream
  without hex/base64 expansion;
- short, long, reordered, duplicated, replayed, altered, and trailing payloads fail closed;
- mutation before helper read, during forwarding, after guest write, and before launch is detected;
- helper and guest allocation limits are exercised at `MAX`, `MAX + 1`, and declared/actual length
  mismatch;
- guest launch is impossible until the post-close rehash succeeds;
- the root-owned staged tarball cannot be replaced, renamed, hard-linked, or modified by the package
  UID;
- prelaunch and postrun guest hashes equal the CAS lease digest.

### Swift helper and VM lifecycle tests

- the artifact configuration validates with `networkDevices.isEmpty` and contains no NAT attachment;
- the legacy project configuration remains separate and cannot be selected by an artifact spec;
- a stopped measured base is required, and base identity mismatch fails before cloning;
- APFS clone success is distinguished from a byte copy; unsupported filesystem and clone failure
  have no persistent-disk fallback;
- every scenario has a unique clone and VSOCK session;
- VM start failure, guest readiness failure, transport failure, timeout, evidence failure, stop
  failure, and deletion failure all preserve the primary error and attempt bounded cleanup;
- successful evidence is returned only after VM stop and verified clone-path absence;
- the base disk digest is unchanged by an inert campaign.

### Guest supervisor tests

- the supervisor is root-owned while npm, lifecycle scripts, Node children, and probes all have the
  recorded nonzero package UID/GID and no supplementary privileged group;
- the package UID cannot modify the supervisor, toolchain, staged artifact, config, control channel,
  or evidence staging;
- the fixed command template uses no runner `/bin/sh -c`, registry target, host path, or uncontrolled
  environment variable;
- the exact local tgz reaches declared lifecycle hooks under both CI profiles with no public
  resolution;
- a package that declares a dependency is rejected by the compiler, and a forged run spec cannot
  make npm fetch it;
- missing or mismatched Node/npm tooling fails closed;
- ordinary exit, nonzero exit, timeout, signal resistance, background child, double-fork,
  reparenting, `setsid`, and local TCP/UDP listener fixtures leave no unaccounted process or listener;
- deliberate sensor loss or enumeration failure produces incomplete evidence;
- fixture markers cannot create a product finding or clean result.

### Evidence and adversarial tests

- cross-artifact, cross-manifest, cross-scenario, cross-profile, cross-clone, cross-base, stale,
  expired, truncated, unsigned, wrong-key, replayed, and field-removal evidence fails verification;
- a run under challenge A cannot be relabeled under challenge B;
- a clean later record cannot erase an earlier positive observation;
- signature validity cannot upgrade missing telemetry or failed teardown to complete;
- guest-provided verdict fields and sync fields are unknown-field errors;
- stdout, stderr, package bytes, canary values, raw paths, VM disks, and restricted telemetry do not
  appear in sanitized evidence or tracked fixtures;
- `can_authorize_allow()` is false for complete, incomplete, positive, failed, and authenticated
  evidence.

### Repository checks for each landing

- focused Rust tests, then the full Rust workspace tests;
- `cargo fmt --all -- --check`;
- Clippy for all targets with warnings denied;
- rustdoc with warnings denied;
- Swift helper tests and build;
- C warnings-as-errors syntax/build checks and guest protocol harnesses;
- tracked shell syntax checks;
- link, ASCII, secret, raw-sample, and `git diff --check` scans for documentation and fixtures.

No generic failure is accepted as proof that a lifecycle trigger, UID transition, no-NIC topology,
guest rehash, descendant teardown, or clone destruction worked.

## First-Slice Acceptance Gates

| Gate | Required evidence |
| --- | --- |
| S1: compiler | Exact inert npm manifest deterministically produces the two typed scenarios; every unsupported shape fails before execution. |
| S2: exact transport | CAS lease, helper receive/send, and guest write/prelaunch/postrun digest and length all match; all mutation and truncation tests fail closed. |
| S3: disposable VM | One stopped measured base creates one proven APFS clone per scenario; the base is never attached writable; every clone is absent after the run. |
| S4: no NIC | Both scenarios boot and execute with zero configured network devices and no NAT fallback. |
| S5: privilege | Every package-controlled process has the dedicated nonzero UID/GID; root-owned runner and controls remain unmodified. |
| S6: lifecycle | The dependency-free inert tgz reaches the intended install lifecycle under both CI profiles with no host npm and no guest public resolution. |
| S7: teardown | Background, daemonized, reparented, escaped-session, signal-resistant, and listening inert fixtures are killed and accounted for; uncertainty is explicit. |
| S8: no sync | CLI, Rust types, Swift options, VSOCK wire, guest supervisor, result schema, and runtime traces contain no artifact sync operation or guest-file return path. |
| S9: evidence | Strict subject/scenario evidence validates with its honest authority and sensor posture, contains no guest verdict, and can never authorize allow. |
| S10: second host | The inert cloud-Mac campaign reproduces S2 through S9 on a documented macOS/APFS/helper/base/toolchain configuration. |

Passing these gates completes only the dependency-free npm first slice. It does not complete Phase
4 because dependency closures, main/export/bin probes, wheels, sdists, and their build/import/
entry-point scenarios remain. It does not complete Phase 5 because independently trustworthy
process, file, DNS, connection, dropped-event, and sinkhole telemetry remains unqualified.

## Cloud-Mac Inert Validation

The user-provided cloud Mac is appropriate after local unit and helper harnesses pass. The campaign
uses only repository-generated inert tgz fixtures and trusted base-image provisioning. It must not
download, open, unpack, inspect, or execute any restricted sample.

Record before the run:

- cloud provider/host identity at an approved sanitized granularity;
- macOS and Virtualization.framework version;
- APFS volume and clone capability;
- helper signature/digest and build revision;
- base-image generation and post-provisioning measurement;
- guest macOS build, supervisor, Node, and npm identities; and
- exact inert fixture, manifest, policy, compiler, template, run-spec, and protocol digests.

Run at least:

1. one clean dependency-free tgz under both CI profiles;
2. one noncanonical-root CI-gated lifecycle canary under both profiles;
3. transport substitution, truncation, replay, and trailing-byte negative cases;
4. nonzero, timeout, TERM-resistant, background, reparenting, escaped-session, and listener inert
   cases;
5. artifact-path and run-spec forgery attempts from the package UID;
6. forced helper and guest-channel interruption at each lifecycle phase; and
7. repeated sequential scenarios proving unique clone ids, stable base measurement, zero configured
   NICs, no sync path, and verified clone destruction.

The execution VM never gets a NIC. Any trusted provisioning network use occurs outside the scenario
plane, is separately recorded, and cannot be reached by package code. No live C2, sinkhole, proxy,
or second-stage target is contacted in this slice.

Publish only bounded sanitized evidence and exact pass/fail gate results. VM disks, artifact bytes,
raw stdout/stderr, packet data, full process traces, canaries, credentials, and cloud-private paths
remain outside tracked files.

## Explicitly Deferred Work

- nonempty npm dependency closures and target-versus-dependency attribution (`AN-405`);
- npm main/export and bin probes plus broader environment/runtime matrices (`AN-402`, `AN-406`);
- exact wheel install, fresh interpreter, `.pth`, import, and console-entry scenarios (`AN-403`);
- exact sdist build, derived-wheel identity, and second fresh install/probe environment (`AN-404`);
- controlled observable DNS/HTTP(S) sinkhole topology and host-visible network intent (`AN-503`
  through `AN-505`);
- independently protected process/file/network telemetry and protected Mac evidence authority
  (`AN-500` through `AN-507`);
- known-malware regression, benign-friction, and held-out gates; and
- Cloudflare or AWS backend qualification.

Cloud backends remain out of scope until this local contract is detection-credible and the shared
conformance suite exists.

## Real-Malware Prohibition

This document authorizes planning and inert implementation tests only. It does not authorize
downloading, unpacking, inspecting, transporting, or executing real malware; accessing the
restricted eleven-sample corpus; contacting live C2; or fetching a live second stage. Do not run
the restricted corpus on the cloud Mac or in the normal development VM.

Any future four-miss or eleven-sample run still requires the separate custody, operator, provider,
and restricted-lab approval gate in the
[actual-malware evaluation runbook](actual-malware-evaluation.md). Until then, the current 7/11
detection result and zero-safety-failure result remain unchanged.
