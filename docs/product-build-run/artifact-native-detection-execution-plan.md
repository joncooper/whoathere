# WhoaThere Artifact-Native Detection Execution Plan

Date: 2026-07-09

Status: canonical execution plan for the next product milestone

Current execution checkpoint (2026-07-11): the pinned Linux VZ inert candidate now boots on a
physical Apple Silicon Mac and passes all thirteen platform capability checks while preserving no
package execution, no sync-back, and no external route. This closes platform feasibility only; the
backend remains unqualified until protected sensors pass the authenticated 38-case inert matrix.
See the [Linux VZ inert-boot checkpoint](artifact-native-linux-vz-inert-boot-checkpoint-2026-07-11.md).

The first protected-sensor bootstrap now also observes a cgroup-filtered inert fork/exec/exit chain
whose child runs as UID/GID 65534 and cannot read or write the root-only sensor. This remains
unsigned bootstrap evidence rather than a conformance receipt. See the
[process-sensor checkpoint](artifact-native-linux-vz-process-sensor-checkpoint-2026-07-11.md).

The guest now emits one strict ordered process payload with host-validated sequence, cgroup lineage,
heartbeat, drop, health, truncation, and teardown fields. Rust independently maps the same payload
into the existing challenge-bound guest receipt claims, while live signing remains disabled. See
the [ordered process-evidence checkpoint](artifact-native-linux-vz-ordered-process-evidence-checkpoint-2026-07-11.md).

The pinned runtime BTF, actual signed physical-host helper, canonical sensor configurations,
structurally absent root disk, and fresh evidence public keys now form an independently validated
unqualified backend identity. See
the [measured backend-identity checkpoint](artifact-native-linux-vz-measured-backend-identity-checkpoint-2026-07-11.md).

The physical guest now accepts one bounded virtio-vsock challenge, validates its exact inert run
context and measured binaries, derives claims from the ordered fork/exec/exit payload, and returns a
live Ed25519 receipt that independent Swift and Rust implementations verify. See the
[live guest-receipt checkpoint](artifact-native-linux-vz-live-guest-receipt-checkpoint-2026-07-12.md).

The same physical case now also produces a separately signed canonical host packet/lifecycle
receipt. Swift and Rust independently derive and verify both claim sets and accept the first
complete guest-plus-host case with zero frames, stopped VM, destroyed diskless execution instance,
and no authority. The backend remains unqualified because 37 of 38 physical cases are pending. See
the [first complete conformance-case checkpoint](artifact-native-linux-vz-first-complete-conformance-case-checkpoint-2026-07-12.md).

The same measured sensor now also completes protected file open/read/write plus BPF-correlated mmap,
fake persistence, and filesystem-diff evidence. `fork_exec_exit` was rerun on the new exact identity,
so two physical cases now share one backend binding; 36 remain. See the
[file-telemetry checkpoint](artifact-native-linux-vz-file-telemetry-checkpoint-2026-07-12.md).

The distinct closed `mmap_access` case then passed physically on that exact identity and was
independently verified from the signed guest and host evidence. Three of 38 cases now pass on one
backend binding; 35 remain. See the
[mmap checkpoint](artifact-native-linux-vz-mmap-checkpoint-2026-07-12.md).

The process sensor now also proves the closed `double_fork_daemonization` lifecycle with three
kernel-observed forks, one exec, three exits, intermediate-to-daemon PID binding, and protected
subreaper teardown. Because that changed the measured identity, the earlier three cases were rerun
and independently verified on the new exact backend. Four of 38 cases now share one binding; 34
remain. See the
[double-fork checkpoint](artifact-native-linux-vz-double-fork-checkpoint-2026-07-12.md).

The distinct `reparenting` case now binds a package child first to its launcher and then to the
protected subreaper through BPF counts, PID lineage, live procfs parent/credential corroboration,
cgroup membership, and complete reaping. The previous four cases were rerun on the resulting exact
identity. Five of 38 cases now share one backend binding; 33 remain. See the
[reparenting checkpoint](artifact-native-linux-vz-reparenting-checkpoint-2026-07-12.md).

The distinct `setsid_escape` case now proves that the exact unprivileged package child becomes a
new session and process-group leader while retaining its package credentials, parent binding, and
cgroup. Strict Swift and Rust decoders bind the corroborated transition between kernel-observed exec
and exit events. The previous five cases were rerun on the resulting exact identity. Six of 38 cases
now share one backend binding; 32 remain. See the
[session-escape checkpoint](artifact-native-linux-vz-setsid-checkpoint-2026-07-12.md).

The `credential_change` case now binds the trusted launcher's drop into the package sandbox through
exact cgroup-filtered `setgroups`, `setgid`, and `setuid` observations, live procfs credentials, and
strict pre-exec ordering. The previous six cases were rerun on the resulting exact identity. Seven
of 38 cases now share one backend binding; 31 remain. See the
[credential-change checkpoint](artifact-native-linux-vz-credential-checkpoint-2026-07-12.md).

The `dynamic_library_load` case now binds an exact measured shared object through protected
fanotify open evidence, an executable live process mapping, and a separately corroborated
`dlopen`/`dlsym` marker call. The previous seven cases were rerun on the resulting exact identity.
Eight of 38 cases now share one backend binding; 30 remain. See the
[dynamic-library checkpoint](artifact-native-linux-vz-dynamic-library-checkpoint-2026-07-12.md).

The `ipv4_connect` case now binds an unprivileged TCP connect to the RFC 5737 sinkhole through a
cgroup-filtered syscall, live `SYN_SENT` socket state, and exactly one checksum-valid host-observed
TCP SYN. The ephemeral source port is cross-checked across guest and host evidence, and any extra
frame fails closed. The previous eight cases were rerun on the resulting exact identity. Nine of 38
cases now share one backend binding; 29 remain. See the
[IPv4-connect checkpoint](artifact-native-linux-vz-ipv4-connect-checkpoint-2026-07-12.md).

The `ipv6_connect` case now binds an unprivileged TCP connect to the RFC 3849 sinkhole through the
same protected syscall and live-socket evidence, plus exactly one checksum-valid MLDv2 bootstrap
report and one checksum-valid host-observed TCP SYN. The previous nine cases were rerun on the
resulting exact identity. Ten of 38 cases now share one backend binding; 28 remain. See the
[IPv6-connect checkpoint](artifact-native-linux-vz-ipv6-connect-checkpoint-2026-07-12.md).

Primary target: malicious npm and PyPI package detection with static analysis, AI-assisted code
review, and behaviorally instrumented detonation in disposable virtual machines

## 1. Executive Decision

WhoaThere's next milestone is not a broader containment preview, enterprise Vault work, Linux
endpoint expansion, or release polish. The next milestone is **artifact-native detection**.

The product must accept the same npm and PyPI artifacts that developers and package managers use,
analyze those exact bytes, exercise their real install/build/import/entry-point behavior in a fresh
VM, and return package-specific evidence. A generic fail-closed or unsupported result remains a
useful safety outcome, but it does not count as malware detection.

The supplied eleven-sample malicious-package corpus becomes a restricted-lab regression gate:

- All eleven samples must produce package-specific malicious evidence.
- The four current `safe_block` samples must become four package-specific detections.
- No sample may execute on the host, sync output back, reach live C2, fetch a live second stage, or
  leak restricted material into normal logs or committed files.
- A balanced benign corpus must measure false-positive, hard-deny, and manual-review rates.
- A separate held-out, time-split malicious corpus must measure generalization. Passing the known
  eleven prevents regressions; it does not by itself support a broad detection claim.

This plan preserves WhoaThere's strongest existing property - fail-closed containment - while making
detection quality the blocking product criterion.

## 2. Product Target

The down-the-middle workflow is:

```text
package coordinate or artifact file
        |
        v
resolve/fetch inert bytes into quarantine
        |
        v
bind exact artifact digest and safely normalize metadata
        |
        +--> deterministic metadata/rule/AST analysis
        |
        +--> artifact-specific, coverage-accounted AI review
        |
        +--> trigger and detonation scenario planning
                    |
                    v
             fresh disposable VM
                    |
                    v
        protected process/file/network telemetry
                    |
                    v
        provenance-bound evidence envelope
                    |
                    v
        malicious / observed-clean / inconclusive / unsupported / infrastructure-error
```

The same pipeline must serve all entry points:

- direct artifact analysis, such as an npm `.tgz`, Python wheel, or Python sdist;
- package-coordinate analysis, such as an exact npm or PyPI name and version;
- protected `npm install`, `npm ci`, `pip install`, and applicable `uv` workflows;
- an untrusted-repository intake workflow;
- future CI and package-proxy admission.

Package-manager compatibility should come from faithfully reproducing package-manager semantics in
the execution plane, not from converting artifacts into approximate source projects.

## 3. Current-State Findings

### 3.1 What already works

The repository already has meaningful foundations:

- fail-closed command classification and policy;
- source and dependency-form inspection;
- scanner adapters and authenticated receipts;
- package-risk history and version-diff concepts;
- a signed Swift macOS Virtualization helper;
- a VSOCK-connected guest agent;
- VM lifecycle, provisioning, packaging, signing, and notarization machinery;
- bounded project mirroring;
- deny-by-default sync-back with receipt and workspace binding;
- sanitized evidence structures and stable reason codes;
- fixture-based tests for representative npm and Python attack shapes;
- a controlled real-malware evaluation harness and sealed evidence workflow.

These should be evolved rather than discarded.

### 3.2 What the real-malware campaign proved

The July 1 campaign produced two distinct results:

- **Containment result:** eleven of eleven artifacts had no unsafe host execution, sync-back, live C2,
  or normal-log restricted-material leak.
- **Detection result:** seven of eleven produced a behavior-related signal under the campaign's
  scoring rules; four were only generically safe-blocked.

The four misses were:

- `mb-npm-sbx-45.0.2`
- `mb-telnyx-4.87.1-wheel`
- `mb-telnyx-4.87.2-sdist`
- `mb-telnyx-4.87.2-wheel`

The existing 63.6% score must not be described as seven independently observed dynamic detections.
The evaluator counted broad behavior-related reason strings, including static lifecycle, network,
native, or canary signals. The checked-in Step 5 record explicitly described its evidence as static
or package-oriented rather than live-network observation.

### 3.3 Structural causes of the misses

The campaign and product currently operate on project workspaces rather than exact package
artifacts:

- The lab harness extracts npm tarballs, wheels, and sdists, then passes an extraction directory to
  workspace-oriented commands.
- Scanner ecosystem inference expects root-level `package.json`, `pyproject.toml`, or requirements
  files.
- Package-risk discovery has no first-class wheel metadata parser and does not normalize a nested
  sdist package root.
- Empty subject discovery returns a generic no-supported-subject result and causes AI review to be
  `not_applicable`.
- Current artifact hashes are often derived from subject or manifest material rather than the exact
  original package bytes.
- The project mirror excludes `.whl`, `.tgz`, `.zip`, native, and similar package artifacts as risky
  inputs.
- pip detonation supports local `.` and requirements workflows, not exact wheel or sdist installation.
- npm detonation runs `npm install` or `npm ci` in a mirrored project; it does not install an exact
  package tarball into a clean consumer project with an offline dependency closure.
- The guest has no metadata-derived wheel import, `.pth`, console-entry-point, or built-sdist probe.
- Dynamic verdicts are currently based mainly on fixture-created marker files rather than protected
  observation of arbitrary process, file, DNS, or socket behavior.
- The guest agent is installed as a root LaunchDaemon and currently launches package-controlled
  shell commands without dropping to a dedicated unprivileged user.
- Timeout handling can kill the immediate shell without proving complete descendant/process-group
  teardown, allowing background behavior to outlive the nominal scenario.

These are architectural gaps, not four missing signatures.

## 4. Scope

### 4.1 In scope

- Exact npm package tarballs.
- Exact PyPI wheels and source distributions.
- Exact artifact-byte identity and provenance.
- Safe archive normalization and ecosystem metadata parsing.
- Existing scanner composition.
- Deterministic static package analysis.
- AI-assisted artifact code analysis with explicit coverage accounting.
- Version-diff analysis against a verified previous version where available.
- Typed install/build/import/entry-point detonation scenarios.
- Fresh disposable VM execution on Apple Silicon macOS hosts.
- Host-visible or otherwise protected process, filesystem, and network telemetry.
- Default-deny network policy with controlled artifact inputs and sinkhole/proxy behavior.
- A backend-neutral detonation contract.
- Controlled Cloudflare Sandbox and AWS Lambda MicroVM evaluation after local correctness.
- Restricted-lab real-malware regression, benign controls, and held-out evaluation.
- A single user-facing artifact/intake workflow and machine-readable evidence.

### 4.2 Explicitly out of scope for this milestone

- Claiming that any package is proven safe.
- Runtime protection after admitted package code is used by an arbitrary application.
- Broad enterprise Vault deployment or multi-tenant package proxy productionization.
- Windows support.
- Ecosystems other than npm and PyPI/compatible pip flows.
- Automatic sync-back from real-malware or unknown-artifact detonations.
- Direct use of a normal Cloudflare Worker isolate to execute untrusted npm or Python packages.
- Self-hosted Firecracker production infrastructure before managed backends are evaluated.
- Live C2 or live second-stage fetching.
- Committing raw malware, packet captures, VM disks, full restricted telemetry, credentials, or
  canaries to git.

## 5. Security and Product Principles

1. **Exact bytes first.** Every analysis and execution result binds to the SHA-256 of the original
   package artifact.
2. **Artifact semantics, not project approximation.** Execute the package in the same artifact form
   and lifecycle shape a package manager would use.
3. **One artifact, one scenario, one fresh environment.** Never reuse a contaminated execution
   environment for a later malicious job.
4. **The execution plane never grants permission.** It emits bounded evidence; a trusted admission
   layer decides.
5. **AI has asymmetric authority.** AI findings may block or escalate. AI `no_finding` can never
   independently allow.
6. **Incomplete is not clean.** Parser limits, missing telemetry, unsupported triggers, model failure,
   timeouts, and infrastructure errors produce explicit inconclusive or error states.
7. **Protected telemetry beats guest self-report.** Untrusted package code must not be able to suppress
   or forge the only evidence source.
8. **Network deny is separate from network detection.** A denied connection is a safety result;
   observed destination intent is behavioral evidence only when the observation path is proven.
9. **No direct copy-back from a detonation VM.** The artifact-native detection milestone freezes
   sync-back for unknown and malicious artifacts. Future admission must use independently fetched,
   digest-matched inert bytes rather than trusting files produced by a contaminated guest.
10. **Known-corpus success and generalization are separate gates.** Both must be measured honestly.

## 6. Trust Boundaries

### 6.1 Trusted control plane

The trusted control plane owns:

- coordinate validation and policy;
- inert artifact acquisition into quarantine;
- digest calculation and provenance records;
- safe normalization orchestration;
- static scanner and AI job scheduling;
- detonation scenario compilation;
- backend selection;
- evidence schema validation and signature/provenance verification;
- final verdict and admission policy;
- sanitized reporting and restricted-evidence references.

The control plane must not execute artifact-controlled install/build/import code.

### 6.2 Untrusted parsing boundary

Archive parsing and source analysis process attacker-controlled bytes and are therefore their own
security boundary. The implementation must:

- use bounded, reviewed parsers rather than shelling out to workspace-controlled tools;
- run normalization in a constrained process or sandbox where practical;
- reject malformed and ambiguous archives;
- never follow package-controlled links;
- never write outside a fresh private normalization root;
- never execute archive contents;
- record complete coverage or an explicit incomplete status.

### 6.3 Untrusted execution plane

The execution plane contains only:

- a measured immutable base image;
- a root-owned runner and sensor;
- one exact artifact and its digest-bound offline dependency closure;
- fake credentials and canaries created after the environment becomes unique;
- typed scenario inputs;
- a default-deny or controlled sinkhole/proxy network;
- bounded output and telemetry channels.

Package code runs unprivileged. The sensor, evidence signing key/material, and control channel must not
be writable or impersonable by the package user.

### 6.4 Evidence boundary

Only strict, size-limited schemas cross from the execution plane. Raw stdout, paths, filenames,
package metadata, and network values remain untrusted. The control plane validates all enum values,
identifiers, digests, sizes, timestamps, scenario bindings, and completeness claims.

## 7. Core Domain Contracts

The exact names may change during implementation, but the concepts and bindings are required.

### 7.1 `ArtifactEnvelope`

Required fields:

- schema version;
- ecosystem;
- package name and version when known;
- source coordinate and source type;
- acquisition timestamp and method;
- original filename;
- original byte length;
- original SHA-256;
- expected media/archive form based on magic bytes;
- custody or quarantine reference;
- resolver and registry metadata digests;
- policy version;
- whether external dependency resolution is required.

No derived manifest hash may substitute for the original byte digest.

### 7.2 `ArtifactManifest`

Required fields:

- artifact SHA-256 and manifest SHA-256;
- magic-detected format;
- canonical package root;
- normalized package identity;
- every member's stable file id, normalized path, original path, type, mode, size, and digest;
- total member count and expanded size;
- skipped or rejected member records;
- normalization completeness;
- npm lifecycle and `bin` targets;
- npm dependency declarations and offline-closure requirements;
- wheel `METADATA`, `WHEEL`, `RECORD`, `entry_points.txt`, `.pth`, import roots, and native tags;
- sdist `PKG-INFO`, `setup.py`, `setup.cfg`, `pyproject.toml`, build backend, and package roots;
- executable-text inventory;
- native/binary inventory;
- archive anomaly reason codes.

Normalization must reject:

- absolute paths and traversal;
- symlinks, hardlinks, devices, sockets, and FIFOs unless an explicit future policy safely handles
  them;
- duplicate normalized paths;
- case-folding and Unicode-normalization collisions;
- excessive nesting;
- excessive member count;
- excessive individual or aggregate expanded size;
- excessive compression ratio;
- inconsistent wheel `RECORD` or ecosystem identity;
- unsupported or ambiguous multi-root structures.

### 7.3 `StaticFinding`

Each deterministic finding includes:

- rule id and rule version;
- category and severity;
- artifact and manifest digests;
- file id and validated line or byte range;
- trigger surface;
- source-to-sink or capability summary;
- confidence and limitations;
- evidence digest;
- whether it is package-specific, generic-risk, or infrastructure-related.

### 7.4 `ArtifactReviewRequest` and `ArtifactReviewResult`

The AI request binds:

- artifact and manifest digests;
- policy digest;
- provider, immutable model/content digest when available, and generation parameters;
- selected file ids, hashes, and exact chunk ranges;
- deterministic trigger and risk context;
- a coverage manifest describing all executable content and why each item was reviewed, excluded, or
  incomplete.

The result uses a strict JSON schema conceptually equivalent to:

```json
{
  "schema_version": "whoathere.artifact_review.v2",
  "artifact_sha256": "sha256:...",
  "verdict": "suspicious",
  "findings": [
    {
      "category": "credential_exfiltration",
      "severity": "high",
      "file_id": "sha256:...",
      "start_line": 10,
      "end_line": 24,
      "trigger": "npm_postinstall",
      "evidence_digest": "sha256:...",
      "explanation": "Reads credential-like environment values and sends them to a remote endpoint."
    }
  ],
  "coverage_manifest_sha256": "sha256:..."
}
```

Allowed verdicts are `suspicious`, `no_finding`, and `uncertain`. Extra prose, unknown enums,
invalid file references, invalid line ranges, digest mismatch, malformed JSON, timeout, provider
failure, or incomplete required coverage yields `error` or `uncertain`; there is no substring-based
fallback to a clean result.

### 7.5 `DetonationSpec`

Required fields:

- job id and idempotency key;
- artifact, manifest, and dependency-closure digests;
- runner image, guest agent, sensor, policy, and schema digests;
- backend capability requirements;
- OS and architecture profile;
- package runtime versions;
- typed scenarios;
- canary and environment profile ids;
- network profile;
- resource, output, and wall-clock limits;
- required telemetry classes;
- raw restricted-evidence destination;
- sanitized evidence destination;
- cleanup and destruction requirements.

Scenarios are typed data, never package-controlled shell strings.

### 7.6 `EvidenceEnvelope`

Required fields:

- all `DetonationSpec` identities and digests;
- backend instance identity and isolation class;
- start, end, timeout, and termination state;
- scenario-by-scenario completion status;
- process ancestry and execution events;
- file, credential/canary, and persistence events;
- DNS, socket, HTTP(S), private-address, and metadata-address events;
- monotonic event sequence ranges, heartbeat state, dropped-event counts, and sensor clock state;
- filesystem diff summary;
- tool exit and timeout evidence;
- sensor health and coverage completeness;
- bounded stdout/stderr digests rather than unrestricted raw output;
- restricted raw-trace object digests;
- evidence signature or authenticated provenance, key id, creation time, expiry, and supersession
  state;
- positive environment-destruction evidence.

The final verifier rejects missing, stale, mismatched, overpermissive, forged, incomplete, or
wrong-scenario evidence.

### 7.7 `VerdictEnvelope`

Required fields:

- exact artifact, manifest, dependency-closure, scenario, platform, runtime, and policy bindings;
- separately represented static, scanner, AI, dynamic, provenance, and infrastructure findings;
- evidence references for every finding;
- aggregation-policy and evidence-profile versions;
- coverage and completeness result;
- issuer identity, signature, key id, creation time, expiry, revocation, and supersession state;
- permitted-use context, such as report-only, manual-review, deny, or eligible for a separately
  defined admission workflow.

No guest-generated verdict is authoritative. The trusted control plane constructs and signs the
`VerdictEnvelope` only after verifying all required evidence.

## 8. Package Trigger Matrix

### 8.1 npm tarball

Required baseline scenarios:

1. Validate exact tarball identity and normalized `package.json`.
2. Create a clean consumer project in the guest.
3. Install the exact local tarball with lifecycle scripts enabled and no public fallback.
4. Exercise `preinstall`, `install`, `postinstall`, and `prepare` where package semantics make them
   applicable.
5. Load the package through the declared main/export entry where safely possible.
6. Invoke declared package `bin` entry points with bounded benign arguments such as `--help` only
   when scenario policy permits.
7. Repeat relevant install/import probes under environment profiles including `CI=true` and
   `CI=false`.
8. Run applicable platform profiles.
9. Observe dependency-closure activity without allowing uncontrolled public resolution.

`mb-npm-sbx-45.0.2` specifically requires generic coverage for lifecycle-triggered credential or
environment access, CI-gated activation, subprocess behavior, and HTTPS/Slack-style exfiltration
intent. The implementation must target these behavior classes, not the sample name or hash.

### 8.2 PyPI wheel

Required baseline scenarios:

1. Validate exact wheel bytes and parse wheel metadata.
2. Install the exact wheel with `pip --no-index` into a fresh target or virtual environment.
3. Start a fresh interpreter so `.pth` and startup behavior can activate normally.
4. Import every validated top-level import root derived from metadata and package layout.
5. Exercise declared console entry points with bounded benign arguments where policy permits.
6. Exercise import-time and selected zero-argument API probes under explicit scenario policy.
7. Record native extension loading and keep unsupported architecture classes distinct from generic
   malware detection.

The two Telnyx wheel samples require coverage for import and console-script triggers, credential or
environment access, HTTPS exfiltration intent, and second-stage-fetch behavior.

### 8.3 PyPI sdist

Required baseline scenarios:

1. Validate the exact sdist and canonicalize its package root.
2. Parse `PKG-INFO`, `pyproject.toml`, `setup.py`, and `setup.cfg` without executing them.
3. Build the exact sdist through the declared PEP 517 backend or legacy path in a fresh guest with a
   digest-bound offline build-tool closure.
4. Record all build-time process, file, and network behavior.
5. Hash and inspect the resulting wheel as a derived artifact, but never trust it for host copy-back.
6. Install the derived wheel in a second fresh scenario or environment.
7. Run the wheel import, `.pth`, and entry-point matrix.

The Telnyx sdist requires generic setup/PEP-517-trigger coverage plus the same credential,
exfiltration, and second-stage behavior classes as the wheel variants.

## 9. AI Analysis Design

The current single workspace-wide Ollama prompt is replaced by an artifact-specific multi-pass
pipeline.

### 9.1 Required passes

1. **Trigger pass:** every npm lifecycle target, build hook, entry point, `.pth`, import root, and
   other automatically invoked surface.
2. **Credential/filesystem pass:** environment access, secret paths, home-directory scanning,
   browser/cloud/SSH/package-manager credentials, and persistence writes.
3. **Network/exfiltration pass:** HTTP(S), DNS, raw sockets, webhooks, metadata services, dynamic URL
   construction, and second-stage fetching.
4. **Process/execution pass:** shell execution, child processes, eval/dynamic import, native loaders,
   encoded commands, and reverse-shell capability.
5. **Obfuscation pass:** high-entropy or encoded blobs, layered decoding, string assembly, dead-code
   gates, minified suspicious additions, and self-modification.
6. **Environment-gating pass:** CI, platform, username, hostname, time, locale, geolocation, secret
   presence, and delayed activation.
7. **Graph pass:** local import/require/caller-callee closure from trigger surfaces to sensitive
   sources and sinks.
8. **Version-diff pass:** new or changed trigger surfaces and suspicious behavior relative to a
   verified prior version.
9. **Synthesis pass:** combine only validated structured findings and coverage records.

### 9.2 Coverage requirements

- Every executable-text member appears in the coverage manifest.
- Large files are chunked by syntax or line boundary rather than skipped.
- Deep files, shell scripts, JSX/TSX, PowerShell, extensionless executables, `.pth`, metadata files,
  and generated-looking sources are handled explicitly.
- Risk windows around deterministic indicators receive surrounding context and graph context.
- Package-controlled text is always data and never trusted instruction.
- Coverage caps produce `incomplete`, never silent omission.
- Model output is never copied onto unrelated package subjects.

### 9.3 Provider policy

- Preserve a local/offline provider for private projects.
- Add a provider-neutral interface so approved hosted models can be evaluated without changing the
  evidence schema.
- Record privacy posture and whether source content left the machine or trust boundary.
- Pin or record a model content/version digest and inference settings for reproducible evaluations.
- Keep model output advisory and independently validated.

## 10. Dynamic Telemetry and Network Design

### 10.1 Required sensor classes

- process start/exit, parent-child lineage, argv digest/redacted summary, and executable identity;
- file open/read/write/rename/delete events for canaries and sensitive path classes;
- environment-canary access where technically observable;
- persistence-related writes and startup-hook creation;
- DNS query intent;
- TCP/UDP connection intent and destination class;
- HTTP(S) host, method class, and sinkhole/proxy outcome where available;
- metadata, loopback, private, link-local, and public destination attempts;
- dynamic library/native module loading;
- before/after filesystem and process-state diff;
- timeout, orphan, daemonization, and forced-kill evidence;
- sensor-health heartbeat and dropped-event accounting.

### 10.2 Sensor trust

The current root-level guest agent both launches package commands and reports marker-derived booleans.
That is insufficient against code that compromises or deceives the guest. The new design separates:

- a root-owned immutable runner/sensor service;
- an unprivileged package execution user;
- host-visible network evidence;
- control-plane verification of sensor identity and coverage;
- a bounded authenticated evidence channel.

At least one important behavior class must be corroborated outside the untrusted package process.
Network evidence should preferably be host-side or platform-side. Filesystem evidence should use a
protected monitor or post-run disk/output diff in addition to package-visible markers.

### 10.3 Network policy

- Default is no public internet.
- Exact artifacts and dependency closures are staged before execution.
- DNS goes to a controlled resolver or a platform path whose query observation has been proven.
- HTTP(S) goes to a controlled proxy/sinkhole when behavior observation is required.
- Non-HTTP traffic is denied and recorded where the backend can prove the attempt.
- Live C2 and live second-stage fetch remain prohibited.
- Scanner and resolver control-plane access is separate from malware execution-plane egress.

## 11. Backend Strategy

### 11.1 Backend-neutral interface

Define:

- `BackendCapabilities`: OS, architecture, runtime versions, package forms, isolation strength,
  telemetry classes, network controls, resource limits, and freshness model.
- `BackendLifecycle`: submit idempotently, poll or stream bounded status, cancel, collect evidence,
  and destroy.
- capability matching that refuses jobs when required triggers or telemetry are unavailable.

The backend returns evidence only. It never returns an authoritative allow decision.

### 11.2 Local Apple Silicon

The existing macOS VM remains the first implementation because it provides native macOS/arm64
fidelity and already has lifecycle, signing, provisioning, and VSOCK foundations.

Required changes:

- clone or restore a trusted clean base for each job or scenario;
- create unique canaries after clone/restore;
- run package code as an unprivileged user;
- destroy the clone after evidence collection;
- stop using direct NAT as the only network/evidence path;
- use a host-controlled custom topology, raw-frame attachment, proxy, or sinkhole;
- bind evidence to helper, base image, guest agent, sensor, scenario, and artifact digests;
- freeze sync-back for artifact-native unknown/malicious jobs.

A small Linux/arm64 Virtualization.framework guest is a later local optimization for high-throughput
cross-platform npm/PyPI coverage. It does not replace the native macOS lane.

### 11.3 Cloudflare

Use a normal Worker, Durable Object, Queue/Workflow, and object storage only for trusted orchestration,
state, AI requests, and evidence handling. Use Cloudflare Sandbox/Containers for untrusted execution.

Evaluation requirements:

- unique sandbox id per artifact/scenario;
- one artifact per sandbox lifetime;
- explicit `enableInternet=false` before startup;
- explicit allowlist only for controlled proxy/sinkhole destinations;
- immediate destroy after evidence collection;
- proof that unprivileged sensors provide required process and filesystem visibility;
- proof of DNS and HTTP(S) observation semantics;
- the same malicious, benign, and telemetry-conformance suite as the local backend.

Cloudflare is accepted only if its measured telemetry satisfies `BackendCapabilities`. Strong
isolation alone is not sufficient.

### 11.4 AWS

Evaluate managed AWS Lambda MicroVMs before self-hosting Firecracker:

- one MicroVM per artifact/scenario;
- custom measured image with root-owned sensor;
- no general ingress;
- VPC or controlled egress connector only to artifact and telemetry services;
- unique runtime payload and canaries;
- snapshot-state reset validation;
- terminate after evidence upload;
- run the shared conformance and corpus suites.

Self-hosted Firecracker is deferred unless managed platforms fail on telemetry, control, cost,
architecture coverage, or reproducibility.

## 12. Verdict Semantics

The product distinguishes:

- `malicious`: package-specific evidence of malicious behavior or high-confidence malicious
  capability is present.
- `suspicious`: meaningful risk evidence exists but malicious intent or trigger completion is not
  sufficiently established.
- `observed_clean`: all required analyses and scenarios completed without findings for the bounded
  profile; this is not a safety proof.
- `inconclusive`: required coverage, telemetry, dependency closure, trigger, or evidence is missing.
- `unsupported`: the package form/platform is explicitly outside current capabilities.
- `infrastructure_error`: a provider, VM, scanner, parser, sensor, or control-plane error prevented a
  valid assessment.

Only `malicious` counts as a detection for known malicious samples. `suspicious`, `inconclusive`,
`unsupported`, manual review, and generic fail-closed outcomes remain safety outcomes and are scored
separately.

Evidence presentation must distinguish:

- static capability detected;
- AI-assisted capability finding;
- dynamically observed behavior;
- blocked network intent;
- sinkhole/proxy-observed behavior;
- generic risk or unsupported form;
- infrastructure failure.

## 13. Evaluation Program

### 13.1 Ordinary CI corpus

Commit only inert semantic fixtures that exercise the same package structures and trigger classes:

- canonical and noncanonical npm tar roots;
- npm lifecycle and `bin` behavior;
- CI-gated inert canary access;
- wheels with imports, `.pth`, entry points, and native tags;
- nested-root sdists with PEP 517 and legacy build paths;
- malicious logic in file middle/tail, files over 64 KiB, deep paths, shell scripts, extensionless
  executables, JSX/TSX, and nested imports;
- archive traversal, link, special-file, collision, duplicate-path, excessive-depth, and expansion
  cases;
- prompt-injection and echoed-JSON cases;
- malformed AI schema and invalid evidence references;
- telemetry conformance fixtures for process, file, DNS, HTTP(S), private-address, and timeout events.

### 13.2 Restricted known-malware regression

- Raw samples remain outside git in the approved custody store.
- Git stores only sanitized sample ids, exact hashes where policy allows, trigger labels, expected
  behavior classes, and sealed evidence references.
- Real-malware execution requires the separate reviewed lab gate; creating this plan or its goal does
  not authorize execution.
- Run the four prior misses first after inert fixtures pass.
- Require four of four package-specific detections.
- Then run the complete eleven and require eleven of eleven.
- Preserve zero unsafe allows, host executions, sync-backs, live C2, live second-stage fetches, and
  normal-log restricted-material leaks.

### 13.3 Benign controls

Use:

- nearest verified-clean neighboring versions for compromised packages where legally and
  operationally appropriate;
- clean packages with legitimate install scripts;
- clean packages with console entry points;
- clean wheels and sdists;
- clean native/binary packages, scored separately if unsupported;
- workflow-heavy public and private fixtures with privacy-safe scanner policy.

The first formal benign qualification cohort should contain at least fifty artifacts distributed
across npm tarballs, wheels, sdists, legitimate lifecycle/build hooks, entry points, and
representative dependency shapes. This is a cohort-size floor, not a substitute for family and
workflow diversity.

Report:

- false malicious rate;
- suspicious/manual-review rate;
- unsupported rate;
- infrastructure-error rate;
- median and tail analysis latency;
- per-stage coverage and failure reasons.

Numeric benign-friction gates must be selected from the first measured baseline rather than invented
without data. The chosen thresholds then become release gates and may not be relaxed because a build
misses them without an explicit reviewed decision.

### 13.4 Held-out malicious evaluation

- Time-split or otherwise isolate samples from development and prompt/rule tuning.
- Freeze code, rules, prompts, model identity, base images, and policy before evaluation.
- Score package-specific static, AI, and dynamic evidence separately.
- Report misses and safe-blocks honestly.
- Do not use known-corpus 100% as the broad detection-rate claim.

## 14. Detailed Execution Plan

### Phase 0 - Canonical baseline and safety freeze

Objective: establish one truthful baseline before implementation changes.

Work packages:

- **AN-000 Repository state:** create or switch to a `codex/` implementation branch from current
  `main`; reconcile `codex/actual-malware-docs-and-handoff` with the source-fixture harness without
  dropping either side.
- **AN-001 Canonical status:** make this plan and the sanitized malware campaign report the canonical
  current status; mark stale planning-era documents as historical rather than silently rewriting
  evidence.
- **AN-002 Evidence baseline:** preserve the 7/11 score, four sample ids, known limitations, exact
  code revision, artifact references, and safety result.
- **AN-003 Threat-model addendum:** document artifact parser attacks, AI prompt injection, guest
  compromise/evidence forgery, dependency-closure poisoning, sensor suppression, snapshot reuse,
  backend confusion, and evidence-store tampering.
- **AN-004 Sync freeze:** enforce and test no sync-back for artifact-native, unknown, and malware lab
  jobs.
- **AN-005 Real-malware authority boundary:** document that implementation and inert tests are
  authorized by the goal, while real-malware runs require the existing separate operator/lab
  approvals.
- **AN-006 Baseline tests:** retain green Rust, Swift, formatting, lint, shell syntax, and existing
  smoke checks.
- **AN-007 Telemetry feasibility spike:** with inert programs only, prove that the proposed macOS
  design can independently observe process creation and descendants, protected file or canary
  access, DNS and connection attempts, dropped-event state, and complete process-tree teardown.
  Time-box the spike and document unsupported signals. The 2026-07-11
  [telemetry feasibility decision](artifact-native-telemetry-feasibility-decision-2026-07-11.md)
  rejects the current macOS-native backend as the bulk lane and selects a lightweight Linux VZ
  guest on the Mac as the candidate. The closed cross-language
  [telemetry-conformance run spec](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md)
  and [authenticated receipt schemas](artifact-native-linux-vz-authenticated-conformance-evidence-checkpoint-2026-07-11.md)
  plus the [complete-matrix qualification mechanism](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)
  now exist. A reproducible, independently verified
  [inert-image candidate](artifact-native-linux-vz-inert-image-candidate-checkpoint-2026-07-11.md)
  and a closed, non-executing
  [inert-fixture contract](artifact-native-linux-vz-inert-fixture-contract-checkpoint-2026-07-11.md)
  also exist, but the image has not booted on a hardware-virtualization-capable Mac. Fixture
  behavior, protected sensors, actual receipts, and the required inert Linux conformance run remain
  open.
- **AN-008 Artifact transport feasibility spike:** replace or prototype beyond the current bounded
  hex-in-JSON project payload so realistic tgz/wheel/sdist sizes can be transported as exact bytes
  with streaming or bounded-memory behavior and end-to-end digest verification.
- **AN-009 Offline closure feasibility spike:** prove an inert npm tarball, wheel, and sdist can reach
  their intended triggers without public execution-plane resolution, including a fixed PEP 517 build
  toolchain and a digest-bound dependency closure.
- **AN-010 CI baseline:** add ordinary CI for Rust tests, formatting, Clippy, Swift tests/build, guest
  protocol tests, shell syntax, and inert fixtures. Restricted malware is never present in ordinary
  CI.

Exit gate:

- Clean branch with both current-main and campaign work represented.
- Canonical baseline document points to immutable evidence.
- Threat model and no-sync policy are reviewed.
- Existing tests remain green.
- Artifact transport, telemetry, descendant teardown, and offline-trigger feasibility decisions are
  recorded. If the macOS guest cannot provide required bulk-runner telemetry, select a lightweight
  Linux guest on the Mac for the bulk lane while retaining macOS for native-fidelity scenarios.
- Ordinary CI protects the non-malware baseline.

### Phase 1 - Artifact identity and safe normalization

Objective: introduce an exact-byte artifact domain independent of workspace discovery.

Work packages:

- **AN-100 Crate boundary:** add a focused artifact crate, tentatively `whoathere-artifact`, rather
  than putting archive parsing into the CLI monolith.
- **AN-101 Artifact envelope:** implement original-byte hashing, quarantine references, media magic,
  coordinate binding, and canonical serialization.
- **AN-102 npm normalizer:** safely parse npm tarballs, canonical and noncanonical roots,
  `package.json`, lifecycle scripts, bins, exports, native markers, and dependency requirements.
- **AN-103 wheel normalizer:** safely parse wheel ZIP structure, dist-info metadata, `RECORD`, tags,
  entry points, `.pth`, import roots, and native extensions.
- **AN-104 sdist normalizer:** safely parse tar/ZIP sdists, find an unambiguous package root, and parse
  `PKG-INFO`, `pyproject.toml`, `setup.py`, and `setup.cfg` as inert data.
- **AN-105 archive defenses:** implement all path, link, collision, member-count, size, depth, and
  expansion-ratio limits with property/fuzz test targets.
- **AN-106 identity integration:** make scanner, package-risk, AI, scenario planning, and evidence use
  `ArtifactEnvelope` and `ArtifactManifest`; retain workspace mode as a separate explicit subject
  type.
- **AN-107 exact hash correction:** remove any use of a subject-derived pseudo-artifact hash where an
  original artifact digest is required.
- **AN-108 Quarantine CAS and TOCTOU:** store immutable inert bytes by digest, install only the bytes
  that were scanned, and test that registry re-resolution or artifact substitution cannot change
  the object between analysis and detonation.

Exit gate:

- Inert npm tgz, wheel, and sdist fixtures yield one correct package identity and complete manifest.
- Unsafe and ambiguous archives fail closed without writing outside the private root.
- Original artifact digest is present and stable through every downstream request.
- The scanned bytes and detonated bytes are proven identical.
- Parser fuzz/property suite has no known escaping or unbounded cases.

### Phase 2 - Deterministic static analysis and version comparison

Objective: catch obvious package attacks without depending on AI or execution.

Work packages:

- **AN-200 Trigger graph:** map lifecycle, build, `.pth`, import, console, bin, export, and native load
  surfaces to exact files.
- **AN-201 Behavior rules:** detect credential/environment access, sensitive path scans, process
  spawning, shell/eval, network clients, DNS behavior, metadata/private addresses, second-stage
  download/execute, reverse-shell capability, persistence, CI/platform/time gates, and obfuscation.
- **AN-202 Language coverage:** cover JavaScript/TypeScript/CommonJS/ESM, Python, shell, `.pth`, and
  package metadata; choose reviewed parser libraries through an ADR rather than adding more fragile
  hand-written parsing.
- **AN-203 Version diff:** bind a verified prior artifact and emphasize new trigger surfaces,
  suspicious code, encoded blobs, native payloads, dependency changes, and entry-point changes.
- **AN-204 Findings contract:** emit validated file/range/evidence-digest `StaticFinding` records.
- **AN-205 Existing scanner composition:** normalize GuardDog, OSV, pip-audit, Syft, Grype, and other
  applicable evidence without allowing scanner cleanliness to authorize.

Exit gate:

- Inert fixtures for each required behavior class emit package-specific findings.
- Findings bind to exact artifact and file digests.
- Clean control fixtures do not receive malicious findings for legitimate lifecycle behavior alone.
- Static analysis coverage and unsupported language forms are explicit.

### Phase 3 - Artifact-specific AI review v2

Objective: provide complete, reproducible, adversarially validated AI-assisted code analysis.

Work packages:

- **AN-300 Provider interface:** separate provider execution from artifact selection and result
  validation; retain local Ollama and allow approved hosted providers later.
- **AN-301 Coverage manifest:** inventory every executable-text item, selected chunks, exclusions,
  deterministic context, and completeness.
- **AN-302 Multi-pass runner:** implement trigger, behavior, graph, diff, and synthesis passes.
- **AN-303 Strict schema:** remove synonym and substring fallback; validate artifact, file, range,
  category, enum, and digest references.
- **AN-304 Prompt-injection defense:** isolate package text as quoted/data content, use fixed system
  instructions, reject echoed or extra schemas, and test adversarial package instructions.
- **AN-305 Authority integration:** findings may block; `no_finding` is advisory; uncertain, error,
  provider failure, timeout, or incomplete coverage fails closed according to policy.
- **AN-306 Reproducibility:** record provider/model identity, content/version digest where possible,
  inference settings, prompt template digest, and request/result digests.
- **AN-307 Privacy:** record local versus hosted source handling and require explicit policy for
  sending private source outside the machine.

Exit gate:

- Malicious inert fixtures hidden beyond previous depth/size/chunk limits are reviewed and found.
- Prompt-injection fixtures cannot produce a clean result or invalid evidence acceptance.
- Every accepted finding has valid file/range evidence.
- Incomplete coverage cannot produce `no_finding` with allow authority.
- AI-clean output cannot override any deterministic, scanner, or dynamic finding.

### Phase 4 - Typed artifact detonation scenarios

Objective: exercise exact package-manager artifact semantics in the VM.

Work packages:

- **AN-400 Scenario compiler:** compile `ArtifactManifest` trigger surfaces into typed scenarios.
- **AN-401 Artifact transport:** add a digest-checked, bounded artifact channel distinct from project
  mirroring; do not unpack restricted artifacts on the developer host as part of normal execution.
- **AN-402 npm consumer workflow:** install exact tgz into a clean consumer project with scripts
  enabled, offline closure, main/export probes, bin probes, and environment profiles.
- **AN-403 wheel workflow:** install exact wheel, start a fresh interpreter, process `.pth`, import
  validated roots, and probe console entry points.
- **AN-404 sdist workflow:** build exact sdist through declared build behavior using a fixed offline
  build closure, capture derived wheel digest, then install/probe in a fresh scenario.
- **AN-405 Dependency closure:** acquire and bind required dependencies without public fallback in the
  execution plane; distinguish target-package behavior from dependency behavior.
- **AN-406 Scenario matrix:** add CI on/off, canary variants, platform/runtime variants, bounded time
  profiles, and applicable import/API triggers.
- **AN-407 Guest privilege split:** package commands run unprivileged beneath a root-owned immutable
  runner and sensor.
- **AN-408 No-sync enforcement:** artifact jobs never request or apply sync-back.
- **AN-409 Complete teardown:** launch each scenario in a dedicated process session/group, terminate
  the full descendant tree, detect surviving/background/listening processes, and fail evidence when
  quiescence cannot be proven.

Exit gate:

- Inert fixtures prove each artifact form reaches its intended lifecycle/build/import/entry-point
  trigger.
- Exact artifact and closure digests are verified inside the guest before execution.
- No public resolution or host package-manager execution occurs.
- No artifact scenario can enable sync-back.
- No descendant from one scenario can survive into another scenario or image snapshot.

### Phase 5 - Protected telemetry and observable egress

Objective: replace synthetic marker-based dynamic claims with independently trustworthy observation.

Work packages:

- **AN-500 Telemetry ADR/prototype:** select platform-appropriate protected sensors and document
  visibility/limitations before choosing implementation.
- **AN-501 Process sensor:** capture process lineage, executable identity, bounded argv summaries,
  exit, backgrounding, and timeout cleanup.
- **AN-502 File/canary sensor:** capture protected canary and sensitive-path reads plus persistence and
  filesystem writes; corroborate with post-run diff.
- **AN-503 Network topology:** replace or supplement direct NAT with a host-controlled custom
  topology, raw-frame path, proxy, or sinkhole.
- **AN-504 DNS/connection sensor:** record DNS and connection intent, destination classes, blocks,
  and dropped-event/coverage state.
- **AN-505 HTTP(S) observation:** record allowed sinkhole/proxy destinations and outcomes without
  permitting live C2 or exposing secrets.
- **AN-506 Evidence authentication:** bind protected telemetry and sensor health to the scenario and
  produce an authenticated `EvidenceEnvelope`.
- **AN-507 Guest-compromise tests:** prove package-user code cannot write sensor binaries/config,
  forge a clean envelope, disable the sensor without detection, or reuse stale evidence.

Exit gate:

- Telemetry conformance fixtures produce expected process, file, DNS, connection, and timeout events.
- A missing or suppressed sensor yields inconclusive/error, never observed-clean.
- Network attempts are blocked by default and observed according to the documented capability.
- Package-controlled marker files are no longer the sole basis of dynamic detection.

### Phase 6 - Verdict engine and evaluation gates

Objective: make detection scoring and release decisions honest and reproducible.

Work packages:

- **AN-600 Verdict model:** implement the explicit verdict semantics in Section 12.
- **AN-600A Signed verdict contract:** implement and validate `VerdictEnvelope`, including issuer,
  freshness, permitted-use, revocation, and supersession semantics.
- **AN-601 Evidence fusion:** distinguish static finding, AI finding, dynamic observation, blocked
  intent, generic risk, unsupported form, and infrastructure failure.
- **AN-602 Scoring rewrite:** remove broad reason-substring scoring and require validated finding or
  observation categories.
- **AN-603 Four-miss lab run:** after separate operator approval, rerun the four prior safe blocks and
  require four of four detections.
- **AN-604 Eleven-sample lab run:** rerun the full known corpus and require eleven of eleven detections
  with zero safety failures.
- **AN-605 Benign baseline:** run the balanced benign corpus and select documented friction gates.
- **AN-606 Held-out evaluation:** freeze the system and run a separate time-split corpus.
- **AN-607 Publication report:** generate a sanitized report separating known-regression,
  held-out-detection, benign-friction, containment, and reproducibility results.

Exit gate:

- Four of four prior misses produce package-specific findings.
- Eleven of eleven known malicious artifacts produce `malicious`.
- Zero unsafe allows, host executions, sync-backs, live C2, live second-stage fetches, or evidence
  leaks.
- Benign metrics and chosen gates are published.
- Held-out results are published without conflating safe blocks with detection.

### Phase 7 - Product workflow and local detection beta

Objective: make the validated pipeline usable through one coherent workflow.

Work packages:

- **AN-700 Primary command:** introduce or refine one artifact/package inspection command that accepts
  an exact coordinate or file and can request detonation.
- **AN-701 Intake integration:** route untrusted-repository package artifacts through the same
  artifact-native pipeline.
- **AN-702 Protected install integration:** make shims/protect behavior call the validated artifact
  pipeline or clearly remain fail-closed; remove the current split between practical VM commands and
  nonexecuting shim architecture.
- **AN-703 Output UX:** show package identity, exact digest, stage status, trigger coverage, static/AI/
  dynamic evidence, limitations, and actionable reason codes.
- **AN-704 Machine output:** stabilize JSON schemas and consider SARIF or an equivalent scanner-friendly
  export for static/AI findings.
- **AN-705 Doctor/readiness:** report artifact parser, model, VM image, sensor, network, and backend
  readiness independently.
- **AN-706 Release gate:** package/sign/notarize a current artifact and require all detection-beta
  gates before distribution.

Exit gate:

- A developer can submit an npm tgz, wheel, sdist, or exact supported coordinate without manually
  unpacking or reshaping it.
- The command returns a truthful bounded verdict and stage-specific evidence.
- Known detection, held-out, benign-friction, safety, and readiness gates all pass at the selected
  release threshold.

### Phase 8 - Backend portability and cloud experiments

Objective: prove the same `DetonationSpec` and `EvidenceEnvelope` across managed cloud execution
backends without weakening local correctness.

Work packages:

- **AN-800 Backend contract extraction:** implement capability negotiation and lifecycle traits around
  the validated local backend.
- **AN-801 Shared conformance suite:** run artifact scenarios, telemetry fixtures, evidence-forgery,
  egress, cleanup, malicious, and benign cases against every backend.
- **AN-802 Cloudflare spike:** implement Worker/control-plane orchestration plus unique Sandbox/
  Container execution with internet disabled and controlled egress.
- **AN-803 Cloudflare decision:** accept, limit, or reject based on measured telemetry and corpus
  coverage.
- **AN-804 AWS Lambda MicroVM spike:** implement managed MicroVM image, egress connector, runner,
  sensor, evidence, and termination flow.
- **AN-805 AWS decision:** accept, limit, or reject based on the same evidence.
- **AN-806 Placement policy:** select local macOS, local Linux, Cloudflare, or AWS only from declared
  artifact/platform/telemetry needs.
- **AN-807 Firecracker decision:** create a separate reviewed goal for self-hosted Firecracker only if
  managed backends fail documented requirements.

Exit gate:

- At least one cloud backend passes the shared contract and security conformance suite, or the report
  honestly concludes that none currently qualify.
- Cloud execution does not change detection or safety semantics.
- Backend limitations are explicit in every evidence envelope.

## 15. Dependency and Parallelization Map

```text
Phase 0 baseline/threat model
        |
        v
Phase 0 feasibility gates (transport, telemetry, closure)
        |
        v
Phase 1 artifact identity/normalization
        |
        +-----------------------+
        |                       |
        v                       v
Phase 2 static analysis    Phase 4 scenario execution foundations
        |                       |
        v                       v
Phase 3 AI review          Phase 5 protected telemetry
        |                       |
        +-----------+-----------+
                    |
                    v
           Phase 6 verdict/evaluation
                    |
                    v
           Phase 7 local product beta
                    |
                    v
           Phase 8 cloud backends
```

Parallel work is safe only after shared schemas are fixed:

- Artifact normalization, static analysis, and AI review can proceed as one track.
- Scenario execution and telemetry can proceed as a second track.
- Evaluation harness, benign corpus design, and documentation can proceed as a third track.
- All tracks converge on exact artifact identity, `DetonationSpec`, and `EvidenceEnvelope`.

Phase 8 must not delay or redefine the local detection gate.

## 16. Repository Landing Map

Recommended landing points:

- `whoathere/crates/whoathere-artifact/` - new exact artifact envelope, normalization, metadata,
  archive defenses, and manifest schemas.
- `whoathere/crates/whoathere-detector/` - deterministic findings over `ArtifactManifest` and source
  members.
- `whoathere/crates/whoathere-evidence/` - static/AI/dynamic evidence types and completeness.
- `whoathere/crates/whoathere-detonation/` - typed scenario compilation, `DetonationSpec`, behavior
  event taxonomy, and evidence fusion helpers.
- `whoathere/crates/whoathere-sandbox/` - backend capability and lifecycle contracts, not package
  artifact parsing.
- `whoathere/crates/whoathere-macos-vm/` - local backend-specific configuration, image/agent/sensor
  bindings, and evidence verification.
- `whoathere/crates/whoathere-source/` - retain workspace/source-policy behavior; add only the bridge
  from package-manager resolution to exact artifact coordinates.
- `whoathere/crates/whoathere-admission/` - final authority and verdict-to-policy decisions.
- `whoathere/crates/whoathere-audit/` - sanitized provenance and evidence summaries.
- `whoathere/crates/whoathere-cli/` - parsing/rendering/orchestration only; extract the current
  artifact review, receipt, and detonation logic rather than expanding the existing monolith.
- `whoathere/helpers/macos-vm-helper/` - disposable clone lifecycle, controlled network attachment,
  and VSOCK transport.
- `whoathere/helpers/macos-vm-helper/guest-agent/` - unprivileged scenario executor plus protected
  sensor integration; remove marker-only authority.
- `scripts/` - release and controlled lab orchestration only; production artifact semantics belong in
  Rust/helper/guest code rather than campaign scripts.
- `docs/product-build-run/` - canonical status, evaluation reports, operator runbooks, and this plan.

The 27,000-line CLI library is a delivery risk. Each phase should move cohesive logic into the
domain crate that owns it while preserving behavior with focused tests.

## 17. Test Matrix

Every implementation phase must run, as applicable:

- unit tests for parsing, schemas, policy, and verdicts;
- property and fuzz tests for archive normalization and evidence decoding;
- integration tests for exact artifact-to-scenario compilation;
- guest-agent/helper tests for each typed scenario;
- telemetry conformance tests;
- egress default-deny and sinkhole/proxy tests;
- evidence tamper, replay, mismatch, stale, and missing-coverage tests;
- AI prompt-injection, malformed-output, invalid-reference, and incomplete-coverage tests;
- benign/malicious inert fixtures;
- full Rust tests, formatting, and Clippy with warnings denied;
- Swift helper tests and build;
- C syntax and guest payload protocol tests;
- shell syntax checks;
- package/release smoke tests at release phases;
- separately approved real-malware runs only at the Phase 6 gates.

No test may use a generic failure as a substitute for proving the intended trigger was reached.
Scenario tests must assert trigger completion and sensor coverage explicitly.

## 18. Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Overfitting the eleven known samples | Require behavior-class fixes, inert semantic fixtures, benign neighbors, and a frozen held-out corpus. |
| Archive parser compromise | Constrained normalization boundary, mature reviewed parsers, strict limits, fuzzing, and no execution. |
| AI prompt injection or false clean | Strict schema and evidence validation, coverage manifest, no substring fallback, and no allow authority. |
| Guest suppresses or forges evidence | Privilege separation, protected sensor, host/platform corroboration, signed provenance, and sensor-health gating. |
| Malware evades one trigger | Metadata-derived typed scenario matrix and multiple environment/platform profiles. |
| Dependency behavior is misattributed | Digest-bound offline closure and per-artifact/per-dependency identity in events. |
| Public network escape | No public execution-plane internet; controlled resolver/proxy/sinkhole and independent egress tests. |
| Snapshot contamination | One artifact/scenario per fresh clone, unique post-clone canaries, and verified destruction. |
| Cloud backend chosen for fashion | Shared capability/conformance suite and measured accept/limit/reject decisions. |
| CLI monolith slows safe change | Move phase-specific domain logic into focused crates with compatibility tests. |
| Safety work is mistaken for real-malware authorization | Explicit lab gate remains separate; plan execution defaults to inert fixtures. |

## 19. Milestone Gates

### M1 - Artifact truth

- Exact npm tgz, wheel, and sdist identities and manifests are correct.
- Unsafe archives fail closed.
- All downstream jobs bind to original bytes.

### M2 - Static and AI coverage

- Trigger graph and deterministic findings cover required behaviors.
- AI review has complete or explicitly incomplete coverage.
- Findings cite validated artifact/file/range evidence.

### M3 - Correct detonation

- Every artifact form reaches the intended package-manager trigger.
- Package execution is unprivileged, offline/controlled, no-sync, and disposable.

### M4 - Real telemetry

- Process, file/canary, DNS/connection, and timeout telemetry pass conformance tests.
- Missing/suppressed sensors cannot yield clean evidence.

### M5 - Known corpus

- Four prior misses: 4/4 malicious.
- Full known corpus: 11/11 malicious.
- Safety invariants: 100% preserved.

### M6 - Detection credibility

- Benign-friction gates pass.
- Held-out results meet a predeclared threshold.
- Reproducibility and sanitized evidence gates pass.

### M7 - Local beta

- One coherent user workflow.
- Current signed/notarized package.
- Machine-readable readiness and all prior gates pass.

### M8 - Cloud portability

- At least one cloud backend passes or all are explicitly rejected with evidence.

## 20. Goal Completion Definition

The execution goal represented by this plan is complete only when:

1. The product ingests exact npm tarballs, PyPI wheels, and PyPI sdists without requiring users to
   manually unpack or reshape them.
2. Exact artifact identity flows through static, scanner, AI, scenario, dynamic, evidence, and
   verdict stages.
3. AI review v2 provides validated artifact-specific findings and explicit coverage.
4. Typed VM scenarios exercise the correct install/build/import/entry-point surfaces.
5. Protected telemetry replaces fixture markers as the authoritative basis for dynamic claims.
6. The four prior misses detect 4/4 and the known corpus detects 11/11 under the separately approved
   restricted lab workflow.
7. The safety invariants remain at zero unsafe host execution, sync-back, live C2, live second-stage
   fetch, and evidence leak.
8. Benign and held-out metrics are measured against predeclared gates.
9. One coherent local macOS-hosted workflow is packaged, documented, signed/notarized as applicable,
   and readiness-verified.
10. Cloudflare and AWS backends are evaluated only after local detection credibility, with at least
    one accepted through the shared conformance contract or an explicit evidence-backed decision that
    no current cloud backend qualifies.

Completing an individual phase, exhausting a budget, producing a generic safe block, or preserving
containment without meeting detection gates does not complete the goal.

## 21. Immediate First Execution Slice

The first implementation slice after goal activation is deliberately small and non-malicious:

1. Reconcile the current main and malware-handoff branch on a `codex/` implementation branch.
2. Add the threat-model/no-sync addendum.
3. Add `ArtifactEnvelope` and `ArtifactManifest` schemas in a new artifact crate.
4. Add inert structural fixtures for:
   - a noncanonical npm tgz with a CI-gated lifecycle canary;
   - a wheel with metadata, `.pth`, imports, and console entry points;
   - a nested-root sdist with PEP 517 and legacy setup surfaces.
5. Write failing tests proving current workspace-only discovery cannot satisfy the new artifact
   contracts.
6. Implement safe normalization until those tests pass.
7. Keep all real-malware execution gates closed.

This slice establishes the exact-byte spine required by every later phase and provides immediate,
reviewable evidence that the product is moving toward the real failure rather than adding unrelated
surface area.

## 22. Evidence and Platform References

Repository evidence:

- [Current product README](../../README.md)
- [Linux VZ inert-boot checkpoint](artifact-native-linux-vz-inert-boot-checkpoint-2026-07-11.md)
- [Linux VZ process-sensor checkpoint](artifact-native-linux-vz-process-sensor-checkpoint-2026-07-11.md)
- [Linux VZ ordered process-evidence checkpoint](artifact-native-linux-vz-ordered-process-evidence-checkpoint-2026-07-11.md)
- [Linux VZ measured backend-identity checkpoint](artifact-native-linux-vz-measured-backend-identity-checkpoint-2026-07-11.md)
- [Linux VZ live guest-receipt checkpoint](artifact-native-linux-vz-live-guest-receipt-checkpoint-2026-07-12.md)
- [Linux VZ first complete conformance-case checkpoint](artifact-native-linux-vz-first-complete-conformance-case-checkpoint-2026-07-12.md)
- [Linux VZ file-telemetry checkpoint](artifact-native-linux-vz-file-telemetry-checkpoint-2026-07-12.md)
- [Linux VZ mmap checkpoint](artifact-native-linux-vz-mmap-checkpoint-2026-07-12.md)
- [Linux VZ double-fork checkpoint](artifact-native-linux-vz-double-fork-checkpoint-2026-07-12.md)
- [Linux VZ reparenting checkpoint](artifact-native-linux-vz-reparenting-checkpoint-2026-07-12.md)
- [Linux VZ session-escape checkpoint](artifact-native-linux-vz-setsid-checkpoint-2026-07-12.md)
- [Linux VZ credential-change checkpoint](artifact-native-linux-vz-credential-checkpoint-2026-07-12.md)
- [Linux VZ dynamic-library checkpoint](artifact-native-linux-vz-dynamic-library-checkpoint-2026-07-12.md)
- [Linux VZ IPv4-connect checkpoint](artifact-native-linux-vz-ipv4-connect-checkpoint-2026-07-12.md)
- [Linux VZ IPv6-connect checkpoint](artifact-native-linux-vz-ipv6-connect-checkpoint-2026-07-12.md)
- [macOS local release readiness](macos-local-release-readiness.md)
- [macOS local beta pressure checkpoint](macos-local-beta-pressure-checkpoint.md)
- [latest source-fixture corpus report](src-fixture-corpus-latest.md)
- Branch `codex/actual-malware-docs-and-handoff`, commit `cc986d1`:
  `docs/product-build-run/whoathere-actual-malware-experimental-run-2026-07-01.html`
- Branch `codex/actual-malware-docs-and-handoff`, commit `cc986d1`:
  `scripts/whoathere-actual-malware-evaluation.py`

Current platform references checked while preparing this plan on 2026-07-09:

- [Apple: Running Linux in a Virtual Machine](https://developer.apple.com/documentation/virtualization/running-linux-in-a-virtual-machine)
- [Apple: Virtualization network attachment options](https://developer.apple.com/documentation/virtualization/vznetworkdeviceattachment)
- [Cloudflare Sandbox security model](https://developers.cloudflare.com/sandbox/concepts/security/)
- [Cloudflare Containers outbound controls](https://developers.cloudflare.com/containers/platform-details/outbound-traffic/)
- [AWS Lambda MicroVMs](https://docs.aws.amazon.com/lambda/latest/dg/lambda-microvms-guide.html)
- [AWS Lambda MicroVM lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/microvms-launching.html)
- [Firecracker project and security model](https://firecracker-microvm.github.io/)

Platform capabilities, limits, availability, and security behavior must be revalidated from current
official documentation before a cloud implementation or deployment decision.
