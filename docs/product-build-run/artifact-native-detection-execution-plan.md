# WhoaThere Artifact-Native Detection Execution Plan

Date: 2026-07-09

Revised: 2026-07-15

Status: canonical detection-first execution plan for the macOS-hosted local beta

## One-sentence goal

Prevent malicious npm and PyPI package artifacts from reaching a developer's host by combining
exact-artifact analysis, Claude and Codex code review, and disposable-VM behavioral evidence while
treating missing evidence as inconclusive rather than safe.

## 1. Executive status and decision

WhoaThere is presently a credible containment and package-workflow admission preview, not a broad
supply-chain malware detector.

The July 1 restricted-lab campaign established two separate results:

- **Containment:** zero host executions, zero sync-backs, zero unsafe allows, and zero
  restricted-material leaks in sanitized evidence across all eleven artifacts.
- **Detection:** seven of eleven artifacts produced behavior-related detections under the campaign
  scorer. Four were only generically safe-blocked, so detection remains **7/11, or 63.6%**.

The four misses are:

- `mb-npm-sbx-45.0.2`;
- `mb-telnyx-4.87.1-wheel`;
- `mb-telnyx-4.87.2-sdist`;
- `mb-telnyx-4.87.2-wheel`.

The execution and telemetry substrate built since that campaign is substantial. The exact Linux VZ
runtime has qualified on inert probes, evidence remains honestly authenticated-but-incomplete, and
npm is closest to a physical end-to-end artifact run. That work did not improve the detection score
by itself. The first package-shaped npm run exposed a specific runtime integration failure before
package completion; pending diagnostic work must be qualified and rerun rather than hidden behind a
generic failure.

The strategic correction is therefore:

1. Finish one detection-bearing artifact path at a time: **npm, then wheel, then sdist**.
2. Build deterministic and AI analysis concurrently with execution, rather than waiting for
   exhaustive telemetry coverage.
3. Repair evaluation before trusting another score.
4. Use the four misses and then all eleven as known-regression gates as soon as inert qualification
   permits a separately approved cloud-Mac campaign.
5. Treat 11/11 as table stakes and regression protection, not proof of broad malware coverage.

Do not pursue IPv6, GSO, full TLS interception, or general protocol expansion unless a failing
detection gate shows that it is necessary. The current goal ends at a credible, usable,
macOS-hosted local detection beta. Cloudflare and AWS portability are a separate follow-on goal.

### July 15 working checkpoint

- The exact npm adapter now validates exported process, file, canary, and network evidence and
  writes a sanitized, digest-bound `behavior-bundle.json` for each completed VM profile.
- `whoathere behavior observe` structurally reloads that bundle, requires its digest to match the
  upstream adapter-reported digest, and invokes the measured native Codex client with saved
  subscription authentication, an empty read-only workspace, no tools or web access, and a strict
  findings-only schema.
- A native inert smoke ran every applicable process, filesystem, credential-and-canary, and network
  specialist. The fused report preserved behavior-specific `lifecycle_trigger_execution`,
  `credential_access`, `canary_access`, and `network_send` findings with exact event-hash citations.
  Unsupported sibling claims were rejected without erasing valid positives. Provider failure, AI
  no-finding, and invalid citations remain inconclusive and can never produce `observed_clean` or
  admission authority.
- The cloud Mac runtime and fresh execution image qualified physically. Exact inert npm execution
  under both `ci_false` and `ci_true`, including a read-only canary fixture, then reproduced
  BLK-001 before authenticated evidence sealing. The observer is ready to consume the first
  completed physical bundle; the sensor pairing redesign remains a separate bounded blocker.

## 2. Product target and claim boundary

The down-the-middle product workflow is:

```text
exact package coordinate or artifact
             |
             v
quarantined acquisition and exact-byte identity
             |
             v
safe normalization and ecosystem metadata
             |
             +--> deterministic metadata, rule, AST, and version-diff analysis
             |
             +--> Claude/Codex artifact review with explicit coverage
             |
             +--> typed scenario compilation
                          |
                          v
              fresh disposable Linux VZ VM
                          |
                          v
            protected process/file/canary/network evidence
                          |
                          v
             observe-only behavioral specialists
                          |
                          v
               strict evidence-derived scorer
                          |
                          v
   malicious / observed-clean / inconclusive / unsupported / infrastructure-error
```

The same original artifact digest must bind normalization, deterministic findings, AI requests,
scenario plans, execution grants, VM evidence, provider receipts, and the final score. A workspace
manifest, extraction-directory hash, package name, corpus label, or advisory may not substitute for
the original bytes.

The beta may claim:

- supported npm and PyPI artifact workflows execute away from the host in a disposable VM;
- copy-back is deny-by-default and evidence-bound;
- supported artifacts receive exact-byte static, AI, and behavioral inspection;
- known and held-out evaluation results are reported under frozen, explicit gates.

The beta may not claim:

- that a package is proven safe;
- arbitrary npm or PyPI coverage;
- low-friction or low-false-positive operation before the benign gates pass;
- live C2 or unrestricted internet-exfiltration detection;
- runtime protection after admitted code is embedded in an arbitrary application;
- enterprise package-proxy, CI-enforcement, or multi-tenant readiness;
- Cloudflare, Firecracker, or AWS readiness before a separate backend conformance campaign.

## 3. Milestones and execution discipline

Three tracks proceed in parallel and converge before real-malware execution:

1. **Artifact execution:** npm, wheel, and sdist end to end.
2. **Analysis and evidence:** deterministic rules, Claude/Codex, behavioral specialists, strict
   verdicts.
3. **Evaluation:** scorer repair, frozen cohorts, benign controls, adversarial controls.

Every engineering slice must end in at least one measurable artifact run, detection fixture, scorer
test, or frozen evaluation result. Do not spend more than one engineering day on infrastructure
without reaching such a checkpoint or documenting the concrete detection gate that requires it.

Use an explicit forest/trees checkpoint whenever one blocker consumes three implementation
iterations or crosses a milestone boundary. Ask whether the work produced a package run, a
behavior-specific detection, a representative fixture, or a more trustworthy release gate. If it
did not, stop the local patch loop and compare the current design with the smallest alternative
that still preserves containment and evidence authenticity. Continuing requires a named detection
gate and a bounded next decision point; telemetry completeness is not, by itself, a reason to delay
artifact coverage.

Paused issues and their exact resume experiments live in the
[detection blocker and revisit queue](detection-blocker-queue.md). An item in that queue is not a
completed milestone and may not be silently reclassified as unsupported or clean.

### Detection-capable alpha

- inert npm, wheel, and sdist workflows pass;
- the 40-artifact development benign cohort is measured;
- the four previous misses become 4/4 behavior-specific detections;
- the full known corpus becomes 11/11;
- all safety invariants remain intact.

This milestone is suitable for report-only and manual-review use, not automatic broad admission.

### Credible local beta

- frozen canonical, mutation, held-out, benign, and unsupported gates pass;
- one coherent package-inspection workflow is signed, packaged, and documented;
- incomplete evidence cannot yield `observed_clean` or automatic admission;
- readiness output identifies every model, policy, runtime, and evidence limitation.

### Cloud follow-on

After the local beta, evaluate Cloudflare orchestration plus isolated execution and AWS managed
microVM/Firecracker-compatible execution against the same backend-neutral contracts. Cloud work
must not delay or redefine local correctness.

## 4. Detection-first artifact slices

### 4.1 npm first

1. Preserve the pending descriptor-collision and specific-failure-code work.
2. Rebuild the diagnostic runtime reproducibly and requalify every changed image, binary, manifest,
   toolchain, and evidence identity.
3. Rerun one purpose-built inert npm tarball under both `CI=false` and `CI=true`.
4. Install the exact local tarball into a clean consumer project with lifecycle scripts enabled and
   no registry fallback.
5. Require authenticated process, file, canary, and available network evidence for each profile.
6. Require the expected inert marker only inside the disposable workspace.
7. Require a stopped VM, destroyed clone, stable immutable images, no public route, and no
   sync-back.

Retained network frames are evidence, not automatic harness failure. A package process that exits
nonzero may still have produced valid malicious evidence. Fixture-only `malware_execution=false`
markers may qualify inert fixtures but are not acceptance conditions for real packages.

### 4.2 Generalize the execution bundle for wheels

Replace npm-specific packaging with a single execution-bundle contract containing:

- schema version and artifact kind;
- generic digest-bound `artifact.bin`;
- exact original artifact digest and length;
- selected typed scenario and ordered action list;
- expected action count;
- optional exact dependency/build closure;
- runtime, policy, telemetry, challenge, grant, and clone bindings.

Qualify a pure-Python wheel through:

1. exact `pip --no-index --no-deps` installation;
2. a fresh interpreter launch that exercises `.pth` behavior;
3. every validated import root in a fresh process;
4. every declared console entry point in a fresh process;
5. a fresh one-use grant and clean environment for each applicable scenario.

Parse `.dist-info/METADATA`, `WHEEL`, `RECORD`, and entry points as first-class metadata. Validate
native/platform tags. Dependencies, missing closure, unsupported native tags, invalid `RECORD`, or
unexercised required triggers produce explicit manual-review, unsupported, or inconclusive results;
they never become clean.

### 4.3 Complete sdists

1. Normalize nested roots before risk analysis or scenario planning.
2. Add the optional exact build-closure transport to the generic bundle.
3. Build a nested-root PEP 517 sdist offline with a sealed tool closure.
4. Normalize and seal exactly one derived wheel, binding it to the original sdist and build
   transcript.
5. Generate `.pth`, import, and entry-point scenarios from that derived artifact rather than source
   guesses.
6. Install and exercise the derived wheel in fresh environments.
7. Add legacy `setup.py` and ZIP-sdist inert controls immediately after the PEP 517 path.

A build failure can carry behavior evidence but cannot establish clean coverage. Multiple or
ambiguous derived wheels, registry fallback, an unsealed build dependency, or source/derived-wheel
identity loss fails closed.

### 4.4 Connect the product spine

One orchestrator must consume the existing prepared exact artifact and invoke, in order:

1. normalization and ecosystem metadata parsing;
2. deterministic and version-diff analysis;
3. Claude/Codex artifact review;
4. typed scenario compilation;
5. disposable-VM execution;
6. independent root-receipt and host-composite verification;
7. typed observation projection;
8. specialist analysis and correlation;
9. strict scoring and admission rendering.

Each stage receives immutable digest-bound inputs and produces a strict, size-limited result. It may
not infer success from a reason-string substring. The orchestrator records partial valid evidence
even when a later stage fails, while the overall completion state remains honest.

### 4.5 Current vertical-slice implementation checkpoint

The existing code is closer to physical wheel and sdist execution than the July campaign result
alone suggests, but several bridges remain claim-critical:

- **npm:** the physical harness remains the leading path, and per-frame `SCM_CREDENTIALS` now bind
  sensor control traffic to the measured runner PID while `SO_PEERCRED` remains structural channel
  evidence. The runtime-v11 CI=true decision run nevertheless stopped on an authenticated orphan
  `sendto` exit with no pending entry. Safety and teardown held, but no package result was accepted;
  CI=false remains unrun. Further stream-protocol patching is paused in favor of the bounded signed
  end-of-action journal described in blocker `BLK-001`.
- **wheel:** metadata-driven install, `.pth`, import-root, and console-entry-point scenario compilers
  and fixed offline process plans already exist. The missing work is an explicit runtime-binding
  fanout bridge, generic physical `artifact.bin` packaging, multi-action evidence, independent
  verification of every root receipt, and an authenticated zero-frame network observation. The
  first wheel fixture must exercise more than one import root and console entry point. The runtime
  must also verify the installed `.pth` surfaces it intended to exercise and define whether console
  coverage means callable activation or execution of the generated wrapper.
- **sdist:** nested-root normalization, exact wheel-only build closure, fixed build plans, and
  exactly-one-derived-wheel sealing already exist in code, but have not run physically. Source
  package-root guesses must not authorize post-build probes. The sdist identity must survive into
  derived-wheel validation; dynamic build requirements must be exercised and fail closed; and an
  authenticated derived-wheel probe manifest must drive `.pth`, import, and entry-point scenarios.
  The first implementation uses a two-pass discovery/probe workflow so every action remains sealed
  before execution.
- **canaries:** the current root-runtime workspace classifies sensitive paths but does not yet seed
  fake npm, PyPI, GitHub, or repository/workflow credentials. Initial inert artifact runs therefore
  qualify trigger and evidence plumbing only. Credential and propagation claims begin only after a
  typed canary-seeding contract and local sinkhole/shim controls are present.

These are detection-bearing gaps, so they take precedence over additional transport or protocol
hardening unless a failing gate demonstrates a new prerequisite.

## 5. Claude and Codex artifact analysis

### 5.1 Provider architecture

Use subscription-authenticated shell clients for the first implementation because they fit the
existing bounded subprocess runtime and avoid a new Node or Python service in the critical path.
Keep the interface transport-neutral so a vendor SDK can replace an adapter later without changing
evidence or verdict semantics. Do not implement CLI and SDK transports simultaneously.

The first adapters are:

- **Claude:** noninteractive `claude -p`, safe mode, no session persistence, plan/dont-ask
  permissions, no built-in tools, no plugins, no MCP, no skills, and strict JSON-schema output.
- **Codex:** `codex exec`, ephemeral session, explicit read-only sandbox, ignored user configuration
  and execution-policy rules, disabled web access, empty private working directory, and strict
  output schema.

The implementation must use vendor-supported saved subscription authentication. It must strip
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CODEX_API_KEY`, and equivalent provider overrides from the
child environment and refuse silent fallback to API-key billing. It must never copy, parse, log, or
repackage subscription OAuth tokens. A scan may not open an interactive login flow.

Provider readiness reports:

- provider and adapter version;
- CLI or SDK version;
- login readiness without exposing credentials;
- observed subscription versus API authentication mode;
- structured-output support;
- isolation/tool/network policy status;
- requested model and available observed model identity;
- timeout, cancellation, and quota readiness.

If readiness cannot prove subscription mode or isolation requirements, the provider is unavailable
and the review result is `uncertain`. `codex exec` officially supports saved CLI authentication,
read-only execution, ephemeral runs, ignored local configuration/rules, and `--output-schema`; these
properties must also be checked against the installed client at runtime. See [Codex non-interactive
mode](https://learn.chatgpt.com/docs/non-interactive-mode) and the [`codex exec` command
reference](https://learn.chatgpt.com/docs/developer-commands?surface=cli#cli-codex-exec). Anthropic's
current subscription guidance is recorded in [Claude Code with Pro or
Max](https://support.claude.com/en/articles/11145838-use-claude-code-with-your-pro-or-max-plan), [Claude
Agent SDK plan usage](https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan),
and the [Claude Code CLI reference](https://code.claude.com/docs/en/cli-usage).

### 5.2 Trusted/untrusted boundary

An AI invocation receives canonical code chunks or verified behavioral projections through an
explicit trusted-envelope/untrusted-content boundary:

- package content is data, never instructions;
- the working directory contains no source checkout, executable artifact, package manager, shell
  script, unrelated file, or writable output target;
- the environment contains no project secrets, canary values, acquisition credentials, user
  configuration, or unrelated provider credentials;
- tool, network, plugin, rule, skill, MCP, hook, and session persistence are disabled;
- the trusted system prompt, threat taxonomy, schema, and evidence catalogue are digest-bound;
- package-controlled text cannot alter the role, request additional access, or redefine evidence;
- model output is validated against artifact, file, byte/line range, event, action, and scenario
  identities before it becomes a finding.

Invalid citations, extra prose, malformed JSON, unknown enums, digest mismatch, timeout, quota
exhaustion, provider failure, or incomplete mandatory coverage yield `uncertain`. Normal logs retain
digests and bounded explanations, not raw package code or restricted telemetry.

### 5.3 Model and receipt identity

Every `AiProviderReceipt` declares one of two identity postures:

- `measured_local_content`: exact local model/content bytes are measured; or
- `provider_hosted_opaque_version`: a hosted provider exposes a name/version but not reproducible
  model bytes.

A hosted receipt records provider, requested and observed model names, CLI/SDK version,
authentication mode, prompt/schema/input/output digests, start/end timestamps, status, coverage, and
available inference controls. It must not invent a `model_content_sha256`, determinism, seed, or
reproducibility property that the provider does not expose.

### 5.4 Arbitration policy

- A configured primary provider performs the complete specialist analysis.
- The second provider independently critiques and correlates the complete evidence bundle.
- A high-risk deterministic signal, incomplete coverage, disagreement, or apparent no-finding
  repeats the affected specialist role with the second provider.
- Qualification and held-out evaluation run the complete graph separately with Claude and Codex and
  report Claude-only, Codex-only, and fused results.
- Either provider's structurally valid positive finding is preserved. A correlator may deduplicate or
  strengthen it but may not erase it.
- Disagreement, provider failure, or incomplete AI coverage yields escalation or `inconclusive`,
  never clean.
- AI `no_finding` has no admission authority.

Public registry artifacts may use hosted review automatically. Private/local source and restricted
malware require explicit policy approval for hosted AI. Without approval, deterministic/local
analysis continues and the hosted-AI lane records manual review or inconclusive.

### 5.5 Required static-review passes

The artifact review graph accounts for every executable member and performs separate passes for:

1. install/build/import/lifecycle triggers;
2. credential, sensitive-file, and filesystem behavior;
3. network, metadata-service, DNS, and exfiltration behavior;
4. child processes, shells, native loading, persistence, and destructive behavior;
5. obfuscation, packing, generated code, invisible text, and staged payloads;
6. CI, platform, locale, username, hostname, secret-presence, and time gates;
7. cross-file call and import graphs;
8. version delta against a verified previous release when available;
9. repository, workflow, package-publish, and self-propagation behavior;
10. synthesis over deterministic signals, release context, and all prior passes.

Coverage must explicitly classify every executable file as reviewed, deterministically covered,
excluded with a valid reason, or incomplete. Truncation is never silently accepted.

## 6. Observe-only behavioral agents

Deterministic collectors remain the only real-time safety and evidence controls. AI agents analyze
strictly verified evidence after an action or scenario; they cannot access the guest, open
networking, kill or allow a process, alter containment, sync files, or declare evidence genuine.

Project each verified action onto one common ordered timeline and five specialist views:

1. **Process and trigger specialist:** lifecycle/import/build activation, ancestry, shells, dynamic
   loading, daemonization, and terminal behavior.
2. **Filesystem specialist:** reads, writes, deletion, persistence, repository mutation, workflow
   mutation, and source-versus-output changes.
3. **Credential and canary specialist:** sensitive path classes, fake-token access, fake-token use,
   and cross-domain correlation.
4. **Network specialist:** DNS, connect/send intent, destination class, metadata access,
   exfiltration, staged downloads, sinkhole interaction, and coverage limitations.
5. **Evasion and propagation specialist:** CI/platform/locale/time gates, obfuscation, self-deletion,
   package/repository propagation, and attempted publication.

Each `SpecialistReport` cites only validated timeline event ids and declares its input coverage. The
top-level correlator receives all specialist reports, deterministic findings, static AI findings,
release context, and coverage flags. It emits cited sequences such as:

```text
CI gate -> credential read -> encoded child process -> outbound connection
```

The correlator may join evidence and raise confidence, but cannot manufacture a missing event,
erase a positive finding, upgrade incomplete coverage, or issue admission authority.

### Bounded follow-up probes

`ProbeRequestV1` is enabled only after the known corpus reaches 11/11 with observe-only analysis.
An agent may request, but never execute, at most two fresh-VM reruns from this closed catalogue:

- CI on/off;
- fake token present/absent;
- fixed locale, platform, username, hostname, or time profile;
- invoke one known lifecycle/import/bin/entry-point trigger;
- extend the bounded observation window;
- enable one predefined local sinkhole service.

Policy validates and either accepts or rejects the typed request. An accepted request compiles into
a new scenario, challenge, grant, clean clone, and evidence binding. Free-form commands, arbitrary
URLs, real credentials, package publication, live C2, live second stages, or host writes are never
valid probes.

## 7. Threat coverage beyond the eleven

Freeze this ten-class taxonomy before further tuning:

1. credential and sensitive-file discovery;
2. DNS, HTTP, exfiltration, and metadata access;
3. second-stage, native, or WASM handoff;
4. process execution, reverse shell, and dynamic loading;
5. obfuscation, packing, invisible content, and string construction;
6. CI, platform, locale, secret-presence, time, and delayed gates;
7. persistence, destructive behavior, and self-deletion;
8. repository, workflow, package-publish, and self-propagation behavior;
9. dependency indirection, confusion, remote sources, and transitive compromise;
10. import/use-time API, data, or cryptographic tampering.

No individual sample is the definition of a class. Rules, fixtures, prompts, specialist schemas,
and held-out cohorts refer to stable class ids and behavior-specific evidence predicates.

### Release context

`ReleaseContext` is a separate risk lane containing:

- requested and resolved package coordinates;
- registry origin and exact artifact URL/digest;
- release age and configured cooldown;
- verified previous version and delta;
- publisher/maintainer and release-workflow continuity;
- source repository reference and source-versus-artifact comparison where verifiable;
- attestations and provenance;
- direct and transitive dependency closure;
- dependency-confusion, package-revival, or ownership-change signals.

Release-context signals may block or escalate, but do not count as behavior detections by
themselves. Valid provenance confirms an origin or workflow claim, not harmlessness, and never
suppresses scanning. This separation reflects documented incidents involving compromised CI,
trusted release workflows, malicious version deltas, and source/artifact disagreement. See the
[TanStack compromise postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem),
[PyPI Ultralytics analysis](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/),
[PyPI aiocpa analysis](https://blog.pypi.org/posts/2024-11-25-aiocpa-attack-analysis/), and [PyPI
attestation security model](https://docs.pypi.org/attestations/security-model/).

Exercise propagation only with fake npm/PyPI/GitHub credentials, instrumented `npm`, `git`, and
`gh` shims, local sinkhole APIs, and repository/workflow canaries. No fixture receives real
publication authority.

## 8. Evidence and evaluation contracts

The exact Rust type names may evolve, but these public concepts, bindings, and failure semantics are
required.

### `ArtifactEnvelope` and `ArtifactManifest`

`ArtifactEnvelope` binds ecosystem, coordinate, acquisition metadata, media type, original length,
original SHA-256, custody reference, registry/resolver evidence, and dependency-resolution need.

`ArtifactManifest` binds the original artifact and records canonical roots and members, normalized
identity, npm lifecycle/bin/dependency metadata, wheel `.dist-info` metadata and native tags, sdist
build metadata and roots, executable/native inventory, and every rejected or incomplete member.
Normalization rejects traversal, absolute paths, unsafe special files, link ambiguity, duplicate or
Unicode/case-colliding paths, excessive counts/sizes/ratios/nesting, inconsistent identity or wheel
records, and ambiguous roots.

### `ArtifactAiProvider` and `AiProviderReceipt`

`ArtifactAiProvider` exposes readiness, bounded analysis, cancellation, and provider-neutral result
semantics. `AiProviderReceipt` binds provider/adapter/model posture, authentication mode,
prompt/schema/input/output identities, timestamps, status, limitations, and coverage.

### `BehaviorAnalysisBundle`

This binds the exact artifact, manifest, runtime, telemetry backend, scenario/action, root receipt,
host-composite receipt, release context, deterministic findings, static AI findings, and verified
ordered process/file/canary/network projections. Raw unverified telemetry cannot enter it.

### `SpecialistReport` and `CorrelationReport`

These contain typed findings, confidence, evidence references, coverage gaps, provider identity,
disagreement records, and typed probe requests. Positive findings are monotonic: correlation may
merge but not remove them.

### `ProbeRequestV1`

This is a closed enum over the allowed follow-up profiles. It records requester, evidence basis,
policy decision, rejection reason when applicable, rerun budget, and the fresh run binding. It has
no general command, URL, environment-map, or file-write field.

### `ReleaseContext`

This binds coordinate, prior release, provenance, source, publisher, workflow, closure, and registry
signals independently from behavior evidence.

### `EvaluationManifestV2`

This freezes:

- manifest and cohort version;
- expected sample id, profile id, artifact digest, ecosystem/form, family/campaign lineage, and
  expected behavior classes;
- required execution, scanner, deterministic, Claude, Codex, dynamic, and fused modalities;
- runtime, prompt, schema, provider-adapter, policy, and scorer identities;
- safety, recall, friction, and completeness thresholds;
- held-out partition and freeze timestamp.

### `RunResultV2`

This records completion and safety state plus typed observations by modality. It contains no
authoritative producer verdict. The evaluator derives the result from the frozen manifest and an
allowlisted behavior/evidence registry.

## 9. Strict scorer semantics

Before any new campaign, the scorer must:

- require exactly one result for every expected sample/profile pair;
- reject missing, duplicate, unreadable, unknown, digest-mismatched, profile-mismatched, stale, or
  extra rows;
- derive verdicts itself rather than trusting a producer-supplied verdict;
- replace reason-substring matching with an allowlisted behavior/evidence registry;
- prevent names, hashes, corpus labels, advisories, reputation, provenance, unsupported-form policy,
  or a generic safe block from satisfying behavior detection;
- score deterministic, scanner, Claude, Codex, dynamic, and fused modalities separately;
- treat inconclusive as a malicious miss and benign friction;
- keep containment/safety and detection quality as independent gates;
- fail the campaign if the denominator, identities, profiles, coverage, or result set is incomplete.

Specific malicious evidence may be detected from a valid authenticated-incomplete envelope. That
does not make the scenario complete. `observed_clean` requires every policy-mandated modality and
scenario to be present, verified, loss-free within its declared limits, and complete. Missing
coverage never implies absence of behavior.

## 10. Acceptance and release gates

### 10.1 Known regression

- all eleven required results are present and complete;
- four previous misses produce 4/4 behavior-specific detections;
- the full corpus produces 11/11 behavior-specific malicious verdicts;
- every artifact matches at least one sealed expected behavior class;
- exact IOC or corpus knowledge alone cannot satisfy the gate;
- zero host execution, sync-back, live C2, live second-stage fetch, invalid teardown,
  restricted-material leak, or unsafe allow.

### 10.2 Canonical and mutation fixtures

- every threat class and package trigger lane has deterministic inert coverage;
- at least two independent canonical fixture families cover each class across applicable ecosystems
  and triggers;
- canonical detection is 100%;
- freeze 120 hidden semantic-preserving variants across at least three parent fixtures per class;
- require at least 95% overall mutation detection and 90% per populated class and trigger lane;
- prompt injection, fake evidence citations, parser confusion, coverage truncation, and sensor
  suppression are 100% prevented from yielding clean;
- at least 40 paired benign transformations produce zero false-malicious results.

### 10.3 Held-out malware

- at least 30 artifacts from at least 12 unrelated campaign or payload families;
- family-level freeze before tuning;
- at least 12 npm artifacts, 8 wheels, 6 sdists, and 8 of the 10 threat classes;
- at least 90% artifact recall and 85% macro family recall;
- at least 80% recall in every artifact-form lane containing five or more samples;
- no represented threat class scores zero;
- class-level claims require multiple independent families;
- confidence intervals are reported and no universal-detection claim is made.

### 10.4 Benign qualification

Use 40 benign artifacts during development, then freeze a separate 120-artifact supported
qualification set containing 40 npm artifacts, 40 wheels, and 40 sdists.

The qualification set includes at least:

- 30 clean neighboring versions of compromised packages;
- 40 legitimate challenge packages with lifecycle, build, process, network, native, or minified
  behavior;
- representative dependency and source/artifact provenance cases.

Require:

- false-malicious at or below 1% overall;
- zero false-malicious results among clean neighbors;
- total friction at or below 10%;
- per-form friction at or below 15%;
- zero unclassified, incomplete, or unresolved infrastructure-error rows in the supported set.

Evaluate at least 20 expected-unsupported controls separately. They must be categorized
conservatively and never become observed-clean.

## 11. Implementation order

### Slice 1: trustworthy npm and scoring

1. Preserve and qualify the pending runtime diagnostic fixes.
2. Complete both inert npm CI profiles.
3. In parallel, implement `EvaluationManifestV2`, `RunResultV2`, strict denominator validation,
   typed scoring, and adversarial scorer tests.

Exit evidence: two physically verified inert npm profiles plus scorer tests proving that missing,
duplicate, generic-block, label-only, mismatched, and incomplete campaigns fail.

### Slice 2: generic bundle and wheel

1. Generalize execution-bundle v2.
2. Parse first-class wheel metadata.
3. Complete install, `.pth`, import-root, and console-entry-point scenarios.
4. Project the signed evidence into typed observations.

Exit evidence: a pure-Python wheel completes every derived action with fresh bindings and no host
effect; unsupported/dependency cases remain explicitly non-clean.

### Slice 3: sdist

1. Normalize nested sdist roots.
2. Add the sealed build closure.
3. Complete PEP 517 build, derived-wheel sealing, wheel-derived probes, legacy setup, and ZIP paths.

Exit evidence: each inert sdist trigger is reached with exact source-to-derived-wheel provenance and
no network fallback.

### Slice 4: Claude/Codex and specialists

1. Extend Artifact Review v2 for hosted opaque model identity and the frozen threat taxonomy.
2. Deprecate the legacy loose-workspace/Ollama path for release decisions.
3. Qualify Claude subscription mode on inert exact artifacts.
4. Qualify Codex subscription mode on the same artifacts.
5. Prove positive findings survive schema validation and authenticated aggregation.
6. Add the five observe-only specialist projections and top-level correlator.

Exit evidence: provider isolation and receipt tests pass; deterministic positives cannot be erased;
prompt injection, invalid citations, provider failure, disagreement, and incomplete coverage cannot
yield clean.

### Slice 5: known regression

1. Run the 40-artifact development benign set and repair practical false positives or unsupported
   paths.
2. Obtain separate restricted-lab authorization.
3. Run the four prior misses on the approved cloud Mac.
4. When 4/4 succeeds, run the full eleven-sample regression.

Exit evidence: 4/4, then 11/11 behavior-specific detection; every safety invariant remains zero;
sanitized evidence only enters tracked paths.

### Slice 6: generalization and local beta

1. Enable bounded typed follow-up probes.
2. Freeze and execute canonical, mutation, held-out, benign, and unsupported cohorts.
3. Correct model/rule/scenario weaknesses without unfreezing held-out lineage.
4. Package one coherent macOS-hosted workflow and readiness report.

Exit evidence: every gate in section 10 passes and the beta claim remains within section 2.

### Separate follow-on: cloud portability

Only after local-beta completion, create a new goal to evaluate Cloudflare orchestration/isolated
execution and AWS managed microVM or self-hosted Firecracker candidates. Use the same artifact,
scenario, evidence, and scoring contracts. Accept a backend only if it passes the shared safety and
telemetry conformance suite; otherwise record an explicit evidence-backed limitation or rejection.

## 12. Test and safety matrix

Each implementation slice runs the applicable subset of:

- unit tests for parsing, schemas, policy, scoring, and arbitration;
- property and fuzz tests for archive normalization and untrusted evidence decoding;
- exact artifact-to-scenario integration tests;
- guest/helper tests for every typed action;
- process, file, canary, network, loss, timeout, teardown, and egress conformance tests;
- signature, tamper, replay, mismatch, stale, duplicate, and missing-coverage tests;
- AI prompt-injection, malformed-output, extra-prose, invalid-reference, quota, timeout, and provider
  disagreement tests;
- benign, malicious-inert, mutation, and source/artifact-difference fixtures;
- Rust tests, formatting, and Clippy with warnings denied;
- Swift helper tests and build;
- C syntax, initramfs, guest protocol, and reproducible-image checks;
- shell syntax and release smoke tests;
- separately approved real-malware campaigns only at the known-regression gates.

No test may use generic failure as a substitute for reaching its intended trigger. Scenario tests
assert trigger completion, evidence binding, declared coverage, VM stop, clone destruction, and
absence of sync-back.

Real malware handling remains unchanged:

- execute it only on the approved cloud Mac inside a fresh disposable Linux VZ guest;
- never execute it in this local workspace or Docker;
- never enable sync-back;
- never contact live C2 or fetch a live second stage;
- keep raw artifacts, quarantine archives, VM disks, packet captures, full telemetry, provider
  details, canaries, credentials, and keys out of tracked paths;
- require a separate reviewed lab gate even when host access is available.

## 13. Goal completion definition

The current execution goal is complete only when:

1. exact npm tarballs, PyPI wheels, and PyPI sdists enter one digest-bound pipeline;
2. deterministic, scanner, Claude, Codex, scenario, dynamic, specialist, and score stages retain the
   original artifact identity;
3. every supported package trigger executes in a fresh, controlled, no-sync disposable VM;
4. protected evidence, not fixture markers, is the authoritative dynamic basis;
5. incomplete evidence never produces observed-clean or automatic admission;
6. the four misses detect 4/4 and the full known corpus detects 11/11 in the separately approved
   lab;
7. all containment invariants remain at zero unsafe outcomes;
8. canonical, mutation, held-out, benign, and unsupported cohorts meet the frozen section 10 gates;
9. one coherent macOS-hosted workflow is packaged, documented, signed/notarized as applicable, and
   readiness-verified.

Completing a substrate checkpoint, exhausting a budget, producing a generic safe block, reaching
11/11 without held-out evaluation, or preserving containment without detection credibility does
not complete the goal. Cloudflare/AWS work is intentionally excluded from this completion
definition.

## 14. Historical evidence appendix

This section replaces the former 980-line chronological preamble. The checkpoint documents retain
the detailed claims, exact identities, test results, and limitations. They are evidence for the
containment, execution, and telemetry substrate; unless a checkpoint explicitly says otherwise,
they did not run a package or malware and did not improve the July 7/11 detection score.

### July 1: actual-malware baseline

- [Final experimental report](whoathere-actual-malware-experimental-run-2026-07-01.html)
- [Evaluation method and claim boundary](actual-malware-evaluation.md)
- [Phase 1 status](actual-malware-phase1-status-2026-07-01.md)
- [Step 5 status](actual-malware-step5-status-2026-07-01.md)
- [Steps 6-8 readiness](actual-malware-steps6-8-readiness-2026-07-01.md)

### July 10: typed wheel transport foundation

- [Scenario compiler](artifact-native-wheel-scenario-compiler-checkpoint-2026-07-10.md), [Mac run
  spec](artifact-native-wheel-mac-run-spec-checkpoint-2026-07-10.md), [helper
  lifecycle](artifact-native-wheel-helper-lifecycle-checkpoint-2026-07-10.md), and [supervisor
  provisioning](artifact-native-wheel-supervisor-provisioning-checkpoint-2026-07-10.md)
- [Guest control framing](artifact-native-wheel-guest-control-framing-checkpoint-2026-07-10.md),
  [guest streaming](artifact-native-wheel-guest-streaming-transport-checkpoint-2026-07-10.md),
  [authenticated transport](artifact-native-wheel-authenticated-transport-checkpoint-2026-07-10.md),
  and [guest authentication](artifact-native-wheel-guest-authentication-checkpoint-2026-07-10.md)
- [Guest staging](artifact-native-wheel-guest-staging-checkpoint-2026-07-10.md), [staging
  receipt](artifact-native-wheel-guest-staging-receipt-checkpoint-2026-07-10.md), and [nonexecuting
  guest session](artifact-native-wheel-nonexecuting-guest-session-checkpoint-2026-07-10.md)

### July 11: Linux VZ feasibility and initial conformance

- [Telemetry feasibility decision](artifact-native-telemetry-feasibility-decision-2026-07-11.md)
- [Inert fixture contract](artifact-native-linux-vz-inert-fixture-contract-checkpoint-2026-07-11.md),
  [inert image candidate](artifact-native-linux-vz-inert-image-candidate-checkpoint-2026-07-11.md),
  and [inert boot](artifact-native-linux-vz-inert-boot-checkpoint-2026-07-11.md)
- [Process sensor](artifact-native-linux-vz-process-sensor-checkpoint-2026-07-11.md), [ordered process
  evidence](artifact-native-linux-vz-ordered-process-evidence-checkpoint-2026-07-11.md), and
  [authenticated conformance evidence](artifact-native-linux-vz-authenticated-conformance-evidence-checkpoint-2026-07-11.md)
- [Measured backend identity](artifact-native-linux-vz-measured-backend-identity-checkpoint-2026-07-11.md),
  [run specification](artifact-native-linux-vz-telemetry-conformance-run-spec-checkpoint-2026-07-11.md),
  [first matrix qualification](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md),
  and [unqualified-backend rejection](artifact-native-linux-vz-unqualified-backend-checkpoint-2026-07-11.md)

### July 12: protected telemetry conformance cases

- [Live guest receipt](artifact-native-linux-vz-live-guest-receipt-checkpoint-2026-07-12.md) and
  [first complete case](artifact-native-linux-vz-first-complete-conformance-case-checkpoint-2026-07-12.md)
- Process behavior: [file telemetry](artifact-native-linux-vz-file-telemetry-checkpoint-2026-07-12.md),
  [`mmap`](artifact-native-linux-vz-mmap-checkpoint-2026-07-12.md), [double
  fork](artifact-native-linux-vz-double-fork-checkpoint-2026-07-12.md),
  [reparenting](artifact-native-linux-vz-reparenting-checkpoint-2026-07-12.md), [session
  escape](artifact-native-linux-vz-setsid-checkpoint-2026-07-12.md), [credential
  change](artifact-native-linux-vz-credential-checkpoint-2026-07-12.md), and [dynamic-library
  loading](artifact-native-linux-vz-dynamic-library-checkpoint-2026-07-12.md)
- Network behavior: [IPv4](artifact-native-linux-vz-ipv4-connect-checkpoint-2026-07-12.md),
  [IPv6](artifact-native-linux-vz-ipv6-connect-checkpoint-2026-07-12.md), [UDP
  send](artifact-native-linux-vz-udp-send-checkpoint-2026-07-12.md),
  [loopback](artifact-native-linux-vz-loopback-connect-checkpoint-2026-07-12.md),
  [link-local](artifact-native-linux-vz-link-local-connect-checkpoint-2026-07-12.md),
  [private-address](artifact-native-linux-vz-private-address-connect-checkpoint-2026-07-12.md),
  [public-address](artifact-native-linux-vz-public-address-connect-checkpoint-2026-07-12.md), and
  [metadata-address](artifact-native-linux-vz-metadata-address-connect-checkpoint-2026-07-12.md)
- DNS behavior: [plaintext](artifact-native-linux-vz-dns-plaintext-checkpoint-2026-07-12.md),
  [encrypted-DNS connect](artifact-native-linux-vz-encrypted-dns-connect-checkpoint-2026-07-12.md),
  and [malformed DNS](artifact-native-linux-vz-dns-malformed-checkpoint-2026-07-12.md)
- Termination behavior: [normal exit](artifact-native-linux-vz-normal-exit-checkpoint-2026-07-12.md),
  [timeout](artifact-native-linux-vz-timeout-checkpoint-2026-07-12.md), [TERM
  resistance](artifact-native-linux-vz-term-resistance-checkpoint-2026-07-12.md), [escaped
  session](artifact-native-linux-vz-escaped-session-checkpoint-2026-07-12.md), [reparented
  child](artifact-native-linux-vz-reparented-child-checkpoint-2026-07-12.md), and [background
  listener](artifact-native-linux-vz-background-listener-checkpoint-2026-07-12.md)
- Faults and loss: [channel interruption](artifact-native-linux-vz-channel-interruption-checkpoint-2026-07-12.md),
  [BPF reservation failure](artifact-native-linux-vz-bpf-reservation-failure-checkpoint-2026-07-12.md),
  [fanotify overflow](artifact-native-linux-vz-fanotify-queue-overflow-checkpoint-2026-07-12.md),
  [host-frame overflow](artifact-native-linux-vz-host-frame-overflow-checkpoint-2026-07-12.md),
  [guest-sensor death](artifact-native-linux-vz-guest-sensor-death-checkpoint-2026-07-12.md), and
  [host-sensor death](artifact-native-linux-vz-host-sensor-death-checkpoint-2026-07-12.md)
- Platform and isolation: [VM stop](artifact-native-linux-vz-vm-stop-checkpoint-2026-07-12.md),
  [package isolation](artifact-native-linux-vz-package-isolation-checkpoint-2026-07-12.md),
  [kernel config/BTF](artifact-native-linux-vz-kernel-config-btf-checkpoint-2026-07-12.md),
  [cgroup v2](artifact-native-linux-vz-cgroup-v2-checkpoint-2026-07-12.md), and [fanotify
  permission](artifact-native-linux-vz-fanotify-permission-checkpoint-2026-07-12.md)

### July 13: qualified backend and package-runtime authority

- [BPF program types](artifact-native-linux-vz-bpf-program-types-checkpoint-2026-07-13.md) and
  [raw-frame/backend qualification](artifact-native-linux-vz-raw-frame-qualification-checkpoint-2026-07-13.md)
- [Package authority request](artifact-native-linux-vz-package-authority-request-checkpoint-2026-07-13.md),
  [pinned package runtime](artifact-native-linux-vz-pinned-package-runtime-candidate-checkpoint-2026-07-13.md),
  [runtime clone preflight](artifact-native-linux-vz-package-runtime-clone-preflight-checkpoint-2026-07-13.md),
  [runtime sensor-alias rebuild](artifact-native-linux-vz-runtime-sensor-alias-rebuild-checkpoint-2026-07-13.md),
  and [root materialization](artifact-native-linux-vz-root-materialization-checkpoint-2026-07-13.md)
- [Runtime qualification request](artifact-native-linux-vz-runtime-qualification-request-checkpoint-2026-07-13.md),
  [receipt protocol](artifact-native-linux-vz-runtime-qualification-receipt-protocol-checkpoint-2026-07-13.md),
  [guest candidate](artifact-native-linux-vz-runtime-qualification-guest-candidate-checkpoint-2026-07-13.md),
  [host launcher](artifact-native-linux-vz-runtime-qualification-host-launcher-checkpoint-2026-07-13.md),
  [physical qualification](artifact-native-linux-vz-runtime-qualification-physical-checkpoint-2026-07-13.md),
  and [qualification record](artifact-native-linux-vz-runtime-qualification-record-checkpoint-2026-07-13.md)
- [Execution grant](artifact-native-linux-vz-package-execution-grant-protocol-checkpoint-2026-07-13.md),
  [execution request](artifact-native-linux-vz-package-execution-request-protocol-checkpoint-2026-07-13.md),
  [runner ingress](artifact-native-linux-vz-package-execution-runner-ingress-checkpoint-2026-07-13.md),
  [closed execution program](artifact-native-linux-vz-closed-execution-program-checkpoint-2026-07-13.md),
  and [fixed process plan](artifact-native-linux-vz-fixed-process-plan-checkpoint-2026-07-13.md)
- [Protected process supervisor](artifact-native-linux-vz-protected-process-supervisor-checkpoint-2026-07-13.md),
  [workspace/derived-wheel boundary](artifact-native-linux-vz-workspace-derived-wheel-checkpoint-2026-07-13.md),
  [protected sequencer](artifact-native-linux-vz-protected-sequencer-checkpoint-2026-07-13.md), and
  [wheel install basename](artifact-native-wheel-install-basename-checkpoint-2026-07-13.md)
- [Sensor payload](artifact-native-linux-vz-package-sensor-payload-checkpoint-2026-07-13.md), [sensor
  control](artifact-native-linux-vz-package-sensor-control-checkpoint-2026-07-13.md), [service
  driver](artifact-native-linux-vz-package-sensor-service-driver-checkpoint-2026-07-13.md), and
  [event stream](artifact-native-linux-vz-package-sensor-event-stream-checkpoint-2026-07-13.md)

### July 14: canonical package evidence

- [BPF producer](artifact-native-linux-vz-package-sensor-bpf-producer-checkpoint-2026-07-14.md),
  [inert BPF qualification](artifact-native-linux-vz-package-sensor-bpf-inert-qualification-checkpoint-2026-07-14.md),
  [selected syscalls](artifact-native-linux-vz-package-sensor-syscall-checkpoint-2026-07-14.md), and
  [process correlator](artifact-native-linux-vz-package-sensor-process-correlator-checkpoint-2026-07-14.md)
- [Terminal binding](artifact-native-linux-vz-package-sensor-terminal-binding-checkpoint-2026-07-14.md),
  [launch binding](artifact-native-linux-vz-package-sensor-launch-binding-checkpoint-2026-07-14.md),
  [kernel exit binding](artifact-native-linux-vz-package-sensor-kernel-exit-binding-checkpoint-2026-07-14.md),
  [terminal reconciliation](artifact-native-linux-vz-package-sensor-terminal-reconciliation-checkpoint-2026-07-14.md),
  and [cross-CPU coverage](artifact-native-linux-vz-package-sensor-cross-cpu-coverage-checkpoint-2026-07-14.md)
- [Root process collector](artifact-native-linux-vz-package-root-process-collector-checkpoint-2026-07-14.md),
  [continuous drain](artifact-native-linux-vz-package-root-process-continuous-drain-checkpoint-2026-07-14.md),
  [fault propagation](artifact-native-linux-vz-package-root-process-fault-propagation-checkpoint-2026-07-14.md),
  and [canonical process evidence](artifact-native-linux-vz-package-root-process-evidence-checkpoint-2026-07-14.md)
- [Canonical file evidence](artifact-native-linux-vz-package-root-file-evidence-checkpoint-2026-07-14.md),
  [network-intent source](artifact-native-linux-vz-package-network-intent-source-checkpoint-2026-07-14.md),
  [canonical network evidence](artifact-native-linux-vz-package-root-network-evidence-checkpoint-2026-07-14.md),
  [cgroup egress](artifact-native-linux-vz-package-cgroup-egress-checkpoint-2026-07-14.md), and
  [canonical egress evidence](artifact-native-linux-vz-package-root-egress-evidence-checkpoint-2026-07-14.md)
- [Root-evidence receipt](artifact-native-linux-vz-package-root-evidence-receipt-checkpoint-2026-07-14.md)

### July 15: authenticated transport, custody, and runtime qualification

- [Authenticated host composition](artifact-native-linux-vz-package-authenticated-host-composition-checkpoint-2026-07-15.md)
  and [independent host-composite verification](artifact-native-linux-vz-package-independent-host-composite-verification-checkpoint-2026-07-15.md)
- [Protected root signer](artifact-native-linux-vz-package-protected-root-signer-checkpoint-2026-07-15.md),
  [authenticated root transport](artifact-native-linux-vz-package-authenticated-root-transport-checkpoint-2026-07-15.md),
  [multi-action sensor session](artifact-native-linux-vz-package-multi-action-sensor-session-checkpoint-2026-07-15.md),
  [concrete root-service entrypoint](artifact-native-linux-vz-package-concrete-root-service-entrypoint-checkpoint-2026-07-15.md),
  and [root-coordinator custody](artifact-native-linux-vz-package-root-coordinator-custody-checkpoint-2026-07-15.md)
- [Execution-runtime qualification](artifact-native-linux-vz-package-execution-runtime-qualification-checkpoint-2026-07-15.md)

### Current product and evaluation references

- [README](../../README.md)
- [macOS local release readiness](macos-local-release-readiness.md)
- [macOS local beta pressure checkpoint](macos-local-beta-pressure-checkpoint.md)
- [macOS local beta CLI guide](macos-local-beta-cli-guide.md)
- [latest source-fixture corpus report](src-fixture-corpus-latest.md)

### Future platform references

These references inform the separate cloud goal and must be revalidated immediately before any
implementation or deployment decision:

- [Apple: Running Linux in a virtual machine](https://developer.apple.com/documentation/virtualization/running-linux-in-a-virtual-machine)
- [Apple: Virtualization network attachments](https://developer.apple.com/documentation/virtualization/vznetworkdeviceattachment)
- [Cloudflare Sandbox security model](https://developers.cloudflare.com/sandbox/concepts/security/)
- [Cloudflare Containers outbound controls](https://developers.cloudflare.com/containers/platform-details/outbound-traffic/)
- [AWS Lambda microVMs](https://docs.aws.amazon.com/lambda/latest/dg/lambda-microvms-guide.html)
- [AWS Lambda microVM lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/microvms-launching.html)
- [Firecracker project and security model](https://firecracker-microvm.github.io/)
