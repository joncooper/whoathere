# GOAL-06: Detection And Detonation

## Objective

Design the package admission pipeline that fetches untrusted packages into quarantine, scans and detonates them, generates explainable verdicts, and promotes only approved artifacts.

## Required Cache-Miss Lifecycle

1. Receive npm metadata/tarball or PyPI Simple API/artifact request.
2. Resolve requested package and candidate artifacts using ecosystem-correct semantics.
3. Fetch metadata and artifact into quarantine CAS.
4. Compute SHA-256/SHA-512 and preserve upstream integrity/hash data.
5. Record origin URL, headers, timestamp, package metadata, platform markers, yanked/deprecated state, and source registry.
6. Run static scanning for manifests, lifecycle scripts, build backend declarations, native binaries, obfuscation, suspicious URLs, install-time code, and known indicators.
7. Evaluate provenance, maintainer/release anomalies, newly added scripts, dependency diffs, and package reputation signals.
8. Detonate selected artifacts across the minimum target matrix.
9. Capture process tree, filesystem writes, network/DNS attempts, environment reads where feasible, and suspicious delays/guards.
10. Produce `allow`, `deny`, `quarantine`, `manual_review`, or `inconclusive` using an artifact-class minimum evidence profile.
11. Promote approved blobs and generated metadata to serving namespace only after the minimum evidence profile passes.
12. Emit audit events and evidence references.

## Required Detonation Matrix

- npm install lifecycle scripts on Linux and macOS target contexts.
- npm import/require smoke execution for representative entrypoints.
- Python wheel install and import smoke execution.
- Python sdist build with PEP 517 backend execution.
- Linux CI context with `CI=true`.
- macOS developer context.
- Native extension build/import where applicable.
- Offline/no-network mode and recorded-egress mode.

## Required Evasion Coverage

- npm `preinstall`, `install`, `postinstall`, `prepare`, and `prepublish`.
- Python `setup.py`, PEP 517 build backends, and import-time payloads.
- DNS TXT/DoH/HTTPS exfiltration.
- Platform-specific npm optional dependencies, `os`/`cpu` selectors, Python wheels, and environment markers.
- Native `.node`, `.so`, `.dylib`, `.pyd`, and compiled extension behavior.
- Maintainer account takeover and suspicious patch/minor release diff.
- Time delays, hostname/user/CI checks, and obfuscated runtime fetches.
- Git/tarball/direct URL and lockfile bypasses.

## Required Deliverables

- `admission-pipeline.md`: end-to-end cache-miss and promotion workflow.
- `scanner-signal-inventory.md`: static, provenance, reputation, vulnerability, and anomaly signals.
- `detonation-matrix.md`: OS, architecture, package-manager, runtime, and environment coverage.
- `evidence-model.md`: process, filesystem, network, DNS, import-time, and verdict evidence format.
- `ADR-009-detonation-runtime.md`: container, VM, microVM, or platform-specific execution decision.
- `manual-review-workflow.md`: quarantine triage, approval, rejection, and evidence display requirements.
- `minimum-allow-verdict-profile.md`: required evidence by ecosystem, artifact/source type, platform, and failure mode.

## Acceptance Criteria

- A malicious package cannot become warm-cache content before an allow verdict bound to complete mandatory evidence for its artifact/source/platform class.
- Install-time, build-time, and import-time behavior are all represented in the pipeline.
- DNS and HTTPS exfiltration attempts are captured or blocked in detonation.
- Platform-specific malicious artifacts are not skipped because the current developer platform differs.
- The pipeline can explain why a package was allowed, denied, quarantined, or sent to manual review.

## Exit Gate

Do not start scanner/detonator implementation planning until the detonation matrix, evidence model, and minimum allow-verdict profile cover every required acceptance-test scenario.

## Suggested Subagents

- Malware detonation reviewer.
- Python packaging/build reviewer.
- npm lifecycle reviewer.
- Native binary analysis reviewer.
