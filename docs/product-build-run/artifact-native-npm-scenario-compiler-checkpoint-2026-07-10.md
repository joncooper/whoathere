# Artifact-Native npm Scenario Compiler Checkpoint

Date: 2026-07-10

Status: backend-neutral, non-executing first-slice compiler and canonical wire implemented; no VM,
package execution, transport, telemetry, evidence-authentication, detection, or admission claim

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native Threat-Model Addendum](artifact-native-threat-model-addendum.md)

## Outcome

WhoaThere now has the first non-executing `AN-400` contract in `whoathere-detonation`. An already
validated, dependency-free inert npm tarball can be compiled into exactly two backend-neutral
scenario templates in deterministic order: one with `CI=false`, then one with `CI=true`. Each
template has distinct trusted job, run, evidence, and scenario identities and is bound to the exact
artifact, acquisition envelope, normalized manifest, canonical quarantine object, policy, empty
dependency closure, runtime profile, lifecycle-command digests, resource ceilings, required
evidence classes, no-network-device requirement, unprivileged-package requirement, and mandatory
clone destruction.

The compiler does not accept artifact bytes directly, launch a helper, invoke npm, construct an npm
command, select a VM, interpret a guest response, or decide a verdict. The executable Mac adapter
remains absent. This is a host control-plane contract checkpoint, not a completed Phase 4 scenario.

## Accepted first-slice shape

Compilation revalidates the envelope, manifest, evidence subject, policy, and trusted execution
identities. It requires:

- npm ecosystem and npm tar-gzip magic format on both envelope and manifest;
- exact artifact, envelope, manifest, and digest-derived CAS-key agreement;
- complete normalization and a present npm package identity and metadata record;
- the repository-receipted inert fixture digest selected by trusted policy;
- an original artifact length within the 64 MiB ceiling;
- no dependency declaration in any normalized npm dependency group;
- no external or offline closure requirement;
- no implicit node-gyp rebuild and no native-binary inventory; and
- only lifecycle hooks qualified by the pinned runtime policy.

The initial policy qualifies `preinstall`, `install`, and `postinstall`. Other normalized lifecycle
hooks, including `prepare`, fail as unsupported until a conformance run proves their exact behavior
for the pinned npm version and local-tarball workflow. The current npm
[install](https://docs.npmjs.com/cli/v11/commands/npm-install/) and
[scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts/) documentation identifies install-time
scripts and newer script-approval behavior, but documentation is not substituted for the required
VM conformance evidence. No npm process was run in this checkpoint.

A dependency, bundled dependency, native member, implicit node-gyp path, unqualified hook,
incomplete manifest, wrong format, subject mismatch, inert-digest mismatch, invalid policy, invalid
identity, or cap failure returns a typed error before a backend can be selected. Unsupported means
the first slice lacks a safe execution plan; it is not a malware finding.

## Closed template and plan wire

Templates and ordered plans use RFC 8785/JCS canonical JSON with closed enums and
`deny_unknown_fields`. Separate domain-separated SHA-256 identities bind the runtime profile,
policy, empty closure, each template, and the ordered plan. The runtime profile binds the measured
Node and npm identities and a fixed command-template identity without carrying executable paths.

The strict template decoder:

- caps input before parsing;
- rejects unknown or duplicate fields, trailing data, whitespace or key-order variants, invalid
  enums and identities, and noncanonical bytes;
- reconstructs and validates the evidence subject and canonical CAS key;
- recomputes the runtime-profile and fixed-command-template digests;
- recomputes the empty-closure digest from the exact manifest identity;
- requires the exact evidence-class set, macOS/arm64 target, no-NIC policy, unprivileged package
  posture, bounded raw-byte transport, and destroy-clone disposition; and
- permits only sorted, unique, currently qualified install-hook bindings.

The plan decoder requires exactly two references in `CI=false`, `CI=true` order with distinct
scenario identities. The canonical template carries no package script text, filesystem path,
registry coordinate or fallback, arbitrary argv, guest output-copy instruction, sync field, or
verdict field. Lifecycle command text remains bound by the exact manifest and by per-hook command
digests, but is not reproduced in the helper wire.

## Structural no-sync posture

There is no sync boolean to set false. `ArtifactScenarioTemplateV1`, `ArtifactScenarioPlanV1`, their
canonical projections, compiler request, policy, and strict decoders have no guest-file return,
host target, output archive, copy-back, or sync variant. The only clone disposition represented by
the first-slice wire is `destroy_clone`.

The legacy project-oriented `vm detonate` types and helper remain unchanged and separate. This
checkpoint does not add a bridge from an artifact scenario into that protocol.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| New artifact-scenario compiler integration tests | 6 passed, 0 failed |
| Existing detonation fixture unit tests | 2 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 679 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |
| `git diff --check` | passed |

The new tests cover canonical and noncanonical package roots, exact two-scenario ordering,
deterministic recompilation, distinct scenario identities, structural absence of sync/argv/registry
and raw command text, strict template and plan decoding, unknown/duplicate/trailing/noncanonical
wire rejection, forged empty-closure rejection, dependency/native/unqualified-hook rejection,
subject and inert-policy binding, and template/plan rebinding when trusted identities or measured
runtime bytes change.

All fixtures were generated inertly in memory. No package lifecycle code, VM, network, cloud Mac,
or restricted sample was used.

## Open work

This checkpoint advances but does not close first-slice gate S1. Additional unsupported-shape and
canonical-vector coverage, the dry non-executing CLI grammar, and backend capability matching still
belong to Landing 1. Gates S2 through S10 remain entirely open.

The next implementation step is the bounded binary submission contract and a separate Mac helper
`artifact-run` parser/lifecycle skeleton. That path must consume only a validated template plus the
exact CAS lease bytes, configure zero network devices, create one proven disposable clone, return
transport/lifecycle observations only, and remain unable to launch npm until the later unprivileged
guest-supervisor landing is complete.

The known-malware result remains 7/11. This checkpoint does not access or change that gate, and it
does not alter the separate approval required for any future restricted-malware run.
