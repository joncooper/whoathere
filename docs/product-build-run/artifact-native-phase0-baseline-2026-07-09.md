# Artifact-Native Detection Phase 0 Baseline

Date: 2026-07-09

Status: active implementation baseline; not a beta-readiness or broad detection claim

## Canonical Record

- Execution scope and gates:
  [artifact-native detection execution plan](artifact-native-detection-execution-plan.md).
- Authoritative campaign outcome:
  [July 1 sanitized experimental report](whoathere-actual-malware-experimental-run-2026-07-01.html).
- Product-wide threat model: [GOAL-01 threat model](../outputs/GOAL-01/threat-model.md).
- Milestone-specific threats:
  [artifact-native threat-model addendum](artifact-native-threat-model-addendum.md).

Older planning and checkpoint documents remain historical evidence for their own revisions. They do
not supersede this baseline or the finalized campaign report.

## Repository Reconciliation

The Phase 0 implementation branch is `codex/artifact-native-detection`.

| Input | Revision | Reconciliation evidence |
| --- | --- | --- |
| Current `main` source-fixture work | `8eb8e54` | Direct parent of the implementation branch; contains the source-fixture corpus harness and current generated report. |
| Malware campaign handoff | `cc986d1` on `codex/actual-malware-docs-and-handoff` | Its patch was replayed on current `main` as `5f56e84`; the commit id changed because the parent changed. |
| Phase 0 starting tree | `5f56e84` | Contains the handoff patch plus the four source-fixture files present on `main`. |

The original handoff commit is therefore not a literal ancestor of the implementation branch. The
content is reconciled: comparing `cc986d1` with `5f56e84` leaves only the source-fixture harness and
its generated JSON/Markdown report from current `main`. This distinction matters for auditability.

## Detection And Safety Baseline

Campaign `whoathere-actual-malware-2026-07-01` finalized on 2026-07-01 with eleven scored malicious
npm/PyPI artifacts.

| Gate | Baseline result | Interpretation |
| --- | --- | --- |
| Package-specific behavior evidence | 7/11 (63.6%) | Failed the then-current 85-90% target and fails the new 11/11 known-corpus gate. The seven results include behavior-related static/package signals and must not be described as seven independently observed dynamic detections. |
| Generic safe blocks | 4/11 | Safe containment, not detection. |
| Unsafe allows | 0 | Safety invariant held for this campaign. |
| Host executions | 0 | Safety invariant held for this campaign. |
| Sync-backs | 0 | Safety invariant held for this campaign. |
| Live C2 and live second-stage fetches | 0 | The run used denied egress/no-live-C2 controls, not full sinkhole/replay telemetry. |
| Restricted material in sanitized output | 0 found | Raw samples, full telemetry, packet captures, VM disks, credentials, and canaries remain outside tracked evidence. |
| Benign controls | Not measured | No false-malicious, manual-review, unsupported, or latency claim is supported. |
| Held-out generalization | Not measured | Passing the known corpus will be a regression result, not a broad detection-rate claim. |

The four required safe-block regressions are:

- `mb-npm-sbx-45.0.2`
- `mb-telnyx-4.87.1-wheel`
- `mb-telnyx-4.87.2-sdist`
- `mb-telnyx-4.87.2-wheel`

The tracked sanitized report does not identify the exact executable code revision used for every
campaign step. A VM state name includes `ff1bb24`, but that path alone does not prove the code
revision. The sealed restricted evidence references in the report remain authoritative; future
campaigns must bind the exact code, policy, model, base image, artifact, scenario, and evidence
revisions explicitly.

## Safety Freeze And Authority Boundary

For the artifact-native milestone:

- Artifact-native, unknown-artifact, and malware-lab jobs must have no sync-back request or apply
  path. A denied or malicious guest is never a source of host files.
- Future admission may use independently acquired, digest-matched inert bytes; it may not trust
  output from a contaminated detonation guest.
- Package code must not execute in the trusted control plane, developer host, or Docker corpus
  custody environment.
- Live C2, public execution-plane resolution, and live second-stage fetching remain prohibited.
- This goal authorizes implementation, documentation, and inert semantic tests only.
- Any real-malware download, unpack, inspection, staging, or execution still requires the existing
  written case, custody controls, two-person operator approval, provider/legal approval where
  applicable, and approved disposable-lab workflow in the
  [actual-malware runbook](actual-malware-evaluation.md).

## Phase 0 Feasibility Gates

No feasibility item below is complete merely because current containment fails closed.

| Gate | Starting evidence | Required decision evidence | Status |
| --- | --- | --- | --- |
| Protected telemetry and descendant teardown (`AN-007`) | Current dynamic authority is mainly guest-reported marker output; timeout handling does not yet prove full descendant teardown. | Inert programs prove independent process lineage, protected file/canary access, DNS and connection intent, dropped-event state, and complete process-tree teardown. Unsupported signals are documented. | [Backend decision recorded](artifact-native-telemetry-feasibility-decision-2026-07-11.md): macOS-native is not bulk-qualified; Linux-on-Mac selected as candidate; inert conformance remains open. |
| Exact artifact transport (`AN-008`) | Current project transport uses a bounded hex-in-JSON mirror and excludes package artifact forms. | An inert tgz, wheel, and sdist cross a bounded/streaming channel as exact bytes with end-to-end digest verification and bounded memory. | Open |
| Offline trigger closure (`AN-009`) | Current guest workflows approximate local projects and do not exercise exact wheel, nested sdist, or clean-consumer npm artifact semantics. | Exact inert npm tgz, wheel, and sdist reach lifecycle/build/import/entry-point triggers with a fixed, digest-bound closure and no public execution-plane fallback. | Open |
| macOS bulk-lane viability | Apple Virtualization provides the current native-fidelity lane, but required protected telemetry is unproven. | Accept the macOS design only if the inert telemetry conformance spike covers required signals; otherwise select a lightweight Linux guest for bulk analysis and retain macOS for Darwin scenarios. | Decision made: retain macOS-native for fidelity/staging and use a lightweight Linux VZ guest as the bulk-lane candidate; qualification pending `AN-007` conformance. |
| Ordinary CI (`AN-010`) | No `.github/workflows` directory exists at the starting revision. | CI runs Rust test/fmt/Clippy, Swift test/build, guest protocol/C checks, shell syntax, and inert artifact fixtures without restricted malware. | Open |

Cloudflare, AWS Lambda MicroVM, and self-hosted Firecracker work is deferred until the local
Mac-hosted artifact pipeline passes exact-byte, scenario, telemetry, evidence, known-corpus, benign,
and held-out gates. A cloud control plane is not itself a detonation environment.

## Existing Non-Malware Test Baseline

These results are inherited evidence from the locally verified pre-implementation `8eb8e54`
checkout. Revision `5f56e84` adds only documentation, scripts, fixtures, and corpus-lab support; it
does not change Rust or Swift product code. This inheritance records the starting point but does not
replace a fresh full rerun before Phase 0 exits.

| Check | Baseline |
| --- | --- |
| `cargo test --manifest-path whoathere/Cargo.toml` | Passed, 528 Rust unit tests plus doctests as applicable. |
| `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check` | Passed. |
| `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings` | Passed. |
| `(cd whoathere/helpers/macos-vm-helper && swift test)` | Passed, 14 Swift tests. |

Phase 0 must also establish current recorded results for Swift build, guest C/protocol checks, shell
syntax, and the existing non-malware smoke scripts listed in `AGENTS.md`. Restricted malware is not
part of this baseline and must never be added to ordinary CI. Test counts are descriptive, not the
gate: all tests and required checks must remain green as coverage grows.

## First-Slice Implementation Evidence

The first non-malicious implementation slice on `codex/artifact-native-detection` now includes:

- a dedicated `whoathere-artifact` crate rather than archive parsing in the CLI monolith;
- `ArtifactEnvelope` original-byte identity and `ArtifactManifest` canonical payload hashing, with
  the manifest digest explicitly excluded from its own hash input;
- strict envelope/manifest deserialization that rejects unknown fields and revalidates schema,
  format/metadata agreement, totals, file ids, inventory references, and manifest digest;
- an in-memory normalized content view keyed by stable file id so deterministic and AI scanners can
  consume the bytes from the same parse rather than independently reparsing the artifact;
- magic-plus-ecosystem format selection for npm tgz, PyPI wheel, tar.gz sdist, and ZIP sdist;
- non-extracting tar/gzip and ZIP readers with explicit member, individual-size, aggregate-size,
  path, depth, metadata, compression-ratio, and trailing-payload limits;
- rejection of absolute/traversal paths, links and special tar members, encrypted or unsupported
  ZIP members, duplicate paths, Unicode/case collisions, file/directory prefix collisions, ZIP
  duplicate central-directory names, local/central-header disagreement, overlap, and appended data;
- inert structural fixtures for a noncanonical npm root with lifecycle/bin/dependency surfaces, a
  wheel with complete `RECORD`, `.pth`, imports, tags, and console entry points, and a nested-root
  PEP 517 sdist with legacy setup surfaces;
- a scope-bound VM sync-back decision type whose artifact-native, unknown-artifact, and restricted
  malware-lab variants cannot produce a helper `--sync-back` argument.

Focused verification at this checkpoint is 18 passing `whoathere-artifact` tests, including exact
one-byte substitution rejection, strict duplicate-key JSON parsing, full TOML PEP 517 parsing, and
unsafe `backend-path` rejection, plus passing crate Clippy with warnings denied and rustfmt. The
existing `whoathere-macos-vm` focused suite is 13 passing tests with its new no-sync cases.

Fresh full-repository verification on the implementation tree passed:

| Check | Current result |
| --- | --- |
| Rust workspace tests and doctests | 549 tests passed; 0 failed. |
| Rust formatting | Passed. |
| Rust workspace Clippy with warnings denied | Passed. |
| Swift helper tests | 14 tests passed; 0 failed. |
| Swift helper build | Passed. |
| Package-risk, scanner-integration, and synthetic attack smoke scripts | Passed. |
| Restricted-lab harness self-test using synthetic metadata only | Passed; no sample access or execution. |
| Guest project-payload and timeout C harnesses | Passed. |
| Offline source-fixture corpus | Passed with zero failures; reports were written only to a temporary directory. |
| Tracked shell syntax | Passed with `bash -n`. |

This is a contract and normalization checkpoint, not Phase 1 completion. ZIP64, bzip2/xz sdists,
persistent quarantine CAS, original-byte transport into a guest, downstream detector/AI/evidence
bindings, a formally standardized cross-language manifest canonicalization, typed execution
scenarios, protected telemetry, and real-corpus detection remain open. No restricted artifact was
accessed or executed to produce this evidence.

## Phase 0 Exit Record

Phase 0 remains open until all of the following have evidence:

- branch/content reconciliation and canonical status (recorded here);
- reviewed threat-model addendum and structural no-sync tests;
- green ordinary non-malware validation and CI;
- accepted artifact transport, telemetry, descendant-teardown, and offline-closure feasibility
  decisions;
- all real-malware execution gates still closed.

No `safe_block`, individual work package, or successful inert fixture closes the broader
artifact-native detection objective.
