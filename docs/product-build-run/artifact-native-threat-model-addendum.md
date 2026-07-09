# Artifact-Native Detection Threat-Model Addendum

Date: 2026-07-09

Status: Phase 0 addendum for review; it does not replace the authoritative threat model

## Relationship To The Authoritative Model

The authoritative product threat model remains
[GOAL-01 threat model](../outputs/GOAL-01/threat-model.md). This addendum narrows that model to the
artifact-native npm and PyPI detection milestone defined by the
[canonical execution plan](artifact-native-detection-execution-plan.md). It adds threats created by
processing exact attacker-controlled package bytes, using AI-assisted source analysis, and executing
typed scenarios in disposable VMs.

The July 1 campaign result and claim boundary remain authoritative in the
[sanitized experimental report](whoathere-actual-malware-experimental-run-2026-07-01.html). This
document does not broaden that result into a general malware-detection claim.

## Security Objectives

1. Bind acquisition, normalization, analysis, detonation, evidence, and verdict to the SHA-256 of
   one immutable original artifact.
2. Never execute package-controlled code in the trusted control plane or on the developer host.
3. Keep package code unprivileged and unable to modify the runner, sensors, evidence authority, or
   base image.
4. Make incomplete parsing, analysis, execution, telemetry, or teardown explicit and fail closed.
5. Prevent unknown or malicious artifact jobs from requesting or applying sync-back.
6. Separate a safety outcome from a detection outcome: containment or generic denial is not proof of
   package-specific malicious behavior.
7. Prevent live C2 and live second-stage retrieval while preserving trustworthy evidence of blocked
   or sinkhole-observed destination intent.

## Additional Assets And Trust Boundaries

Assets added by this milestone include original artifact bytes, quarantine/CAS metadata, dependency
closures, normalized manifests, source and version-diff indexes, AI prompts and responses, scenario
plans, base-image measurements, canary definitions, protected telemetry, evidence-signing material,
and final verdict records.

The added trust boundaries are:

- registry or approved custody source to the inert acquisition/quarantine plane;
- quarantine bytes to the constrained archive parser and normalizer;
- normalized attacker text to deterministic and AI-assisted analyzers;
- trusted scenario compiler to the untrusted VM execution plane;
- offline dependency-closure builder to the guest package manager;
- package user to the root-owned runner and protected sensors;
- sensor output to the evidence authenticator and trusted verdict engine;
- backend-neutral job contract to a specific macOS, future Cloudflare, or future AWS backend;
- sanitized evidence store to operators and normal product reporting.

## Adversary Capabilities

In addition to the capabilities in the authoritative model, assume an artifact author can:

- craft malformed, ambiguous, deeply nested, oversized, colliding, or polyglot archives;
- exploit parser bugs, path normalization differences, links, special files, and decompression limits;
- change registry bytes or dependency resolution between analysis and execution;
- place malicious logic outside size, depth, language, chunk, or call-graph coverage limits;
- embed prompt-injection text or model-output-shaped data in source, metadata, and filenames;
- detect the guest, CI profile, canaries, time budget, platform, network policy, or analysis tooling;
- compromise the package user and attempt to suppress sensors, forge evidence, or leave descendants;
- poison an offline dependency closure or exploit a build frontend/backend before the target trigger;
- exploit snapshot reuse, stale receipts, backend routing, or evidence-store replacement to attach a
  clean result to different bytes or a different scenario.

## Abuse Cases, Required Controls, And Verification

| Threat | Required control | Required verification |
| --- | --- | --- |
| Archive traversal, links, special files, collisions, bombs, or parser exploitation | Parse without execution in a constrained fresh root; enforce member, path, depth, byte, and expansion limits; reject ambiguity; never follow links | Adversarial fixtures, property tests, fuzz targets, and proof that no write escapes the normalization root (`AN-101` through `AN-105`) |
| Artifact substitution or time-of-check/time-of-use mismatch | Immutable digest-addressed quarantine; bind every contract to original SHA-256; verify guest bytes before execution; prohibit registry re-resolution of the target | Mutation/substitution tests proving scanned and detonated bytes are identical (`AN-101`, `AN-106` through `AN-108`, `AN-401`) |
| Package text evades deterministic or AI coverage | Inventory every executable-text member; explicit exclusions and coverage state; trigger graph; bounded chunking without silent truncation; incomplete means inconclusive | Deep, large, tail-loaded, shell, extensionless, and unsupported-language fixtures (`AN-200` through `AN-205`, `AN-301`, `AN-302`) |
| AI prompt injection, schema spoofing, or fabricated citations | Treat artifact content only as quoted data; fixed instructions; strict output schema; validate artifact/file/range/digest citations; no substring fallback; AI has no allow authority | Prompt-injection, echoed-JSON, malformed-schema, invalid-range, and false-clean fixtures (`AN-303` through `AN-306`) |
| Sensitive source disclosure to an unapproved model | Provider policy records local versus hosted handling; private source requires explicit authorization; minimize and audit submitted content | Provider-policy tests and evidence containing provider/model/prompt digests without source leakage (`AN-300`, `AN-306`, `AN-307`) |
| Dependency-closure poisoning or public fallback | Digest-bind every closure member and provenance record; fixed build toolchain; no public execution-plane resolution; attribute target and dependency behavior separately | Inert npm tgz, wheel, and sdist offline-trigger tests plus altered-closure and fallback-denial tests (`AN-009`, `AN-405`) |
| Guest privilege escalation or runner/sensor replacement | Dedicated unprivileged package user; immutable root-owned runner, sensor, config, and control channel; measured base image | Guest-compromise fixtures proving package code cannot modify controls or impersonate the evidence source (`AN-407`, `AN-507`) |
| Sensor suppression, dropped events, or evidence forgery | Host-visible or otherwise protected independent telemetry; sensor health and dropped-event state; authenticated scenario-bound evidence; fail closed on gaps | Process, file/canary, DNS, connection, and sensor-failure conformance tests (`AN-007`, `AN-500` through `AN-507`) |
| Child process survives timeout or contaminates later work | One artifact and scenario per fresh environment; dedicated process session/group; kill and verify all descendants; require quiescence before evidence finalization | Background, daemon, reparenting, listener, timeout, and teardown fixtures (`AN-007`, `AN-409`) |
| Snapshot reuse leaks prior state or enables delayed behavior | Restore only from a measured immutable clean base; create canaries after uniqueness; destroy or clear every execution environment; reject stale job identity | Cross-scenario contamination and stale-snapshot tests; unique job/scenario/base-image bindings (`AN-409`, `AN-506`, `AN-507`) |
| Network policy is mistaken for network detection | Default-deny or controlled sinkhole topology; separately report blocked intent, observed destination, and coverage; no live C2 or second-stage fetch | DNS/direct-IP/private-address/proxy tests and explicit dropped-event status (`AN-503` through `AN-505`) |
| Backend confusion or capability downgrade | Backend-neutral typed contract plus attested backend identity and capabilities; reject jobs requiring signals a backend cannot provide; qualify cloud only after local correctness | Shared backend conformance suite and downgrade/misrouting tests (`AN-600` through `AN-603`) |
| Evidence replay, tampering, truncation, or store replacement | Canonical, size-limited schema; artifact/scenario/policy/model/base-image bindings; authenticated envelope; append-only or tamper-evident storage; reject stale or duplicate job identities | Signature, replay, field-removal, cross-artifact, cross-scenario, and store-integrity tests (`AN-506`, `AN-700` through `AN-704`) |
| Sync-back from a contaminated guest | Artifact-native, unknown, and malware-lab job types structurally cannot request or apply sync-back; admission uses independently fetched digest-matched inert bytes | CLI, protocol, policy, receipt, and adversarial flag tests proving no artifact scenario reaches sync logic (`AN-004`, `AN-408`) |
| Sanitized output leaks samples, canaries, credentials, or host-private details | Strict allowlisted evidence schema, bounded summaries, redaction, and restricted-evidence references; no raw stdout or packet capture in normal output | Secret/canary/raw-byte/path leak scans over normal logs, reports, and committed fixtures (`AN-702`, `AN-703`) |

## Authority And Verdict Rules

- Deterministic, scanner, AI, and dynamic evidence may block or escalate.
- AI `no_finding`, a clean scanner result, or lack of observed behavior cannot independently allow.
- Parser limits, incomplete AI coverage, sensor gaps, timeouts, teardown uncertainty, unsupported
  triggers, or infrastructure errors cannot become `observed-clean`.
- Package labels and known-corpus membership are evaluation truth only; they are never product
  detections.
- A generic `safe_block` remains a valid safety result but does not satisfy the package-specific
  detection gate.
- No verdict authorizes direct copy-back from an artifact detonation VM.

## Residual Risk And Review Decisions

Dynamic analysis cannot prove a package benign, and finite scenarios cannot cover every production
activation condition. Native code, kernel or hypervisor defects, parser zero-days, model failures,
encrypted second stages, environment-specific triggers, and telemetry blind spots remain residual
risks. The verdict schema must expose these limitations instead of converting them into confidence.

Before Phase 0 exits, reviewers must decide whether the macOS-hosted runner can independently
observe the required process, file, network, dropped-event, and teardown signals. If it cannot, the
bulk lane moves to a lightweight Linux guest on the Mac while macOS remains the native-fidelity
lane. Cloud backends remain unqualified until the local contract and conformance tests exist.

This addendum authorizes documentation and inert fixtures only. It does not authorize downloading,
unpacking, inspecting, or executing real malware. Those actions retain the separate operator,
custody, provider, and restricted-lab approvals in the
[actual-malware evaluation runbook](actual-malware-evaluation.md).
