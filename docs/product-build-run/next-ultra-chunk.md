# Next Ultra Chunk: P05 Paired npm VM/Codex Evidence in the Product Report

Status: complete. P05 passed independent Ultra verification at implementation commit `84f24f6`.
P06 remains queued and was not started in this chunk.

Updated: 2026-07-18

## Immutable execution contract

- Branch: `codex/p05-paired-npm-report`, based on accepted P04 commit `96aae35`.
- Budget: 2-4 hours of focused implementation, excluding independent verification.
- One read-only Ultra input audit and one final independent Ultra verification are allowed.
- No cloud host, VM, raw malware, package bytes, hosted AI invocation, or restricted access is
  required in this chunk.
- At four focused implementation hours, stop and park the exact remaining blocker. Do not turn P05
  into a new scorer, telemetry system, evidence protocol, or general reconciliation framework.

Primary metric: the existing npm `BLOCK` report renders two separately labeled CI profiles with
validated lifecycle, credential-file-read, local-sinkhole connect/send, and Codex evidence while
remaining visibly incomplete, diagnostic-only, and non-authoritative.

## User-facing outcome

The user runs the existing saved-report command with one optional versioned reconciliation file:

```text
whoathere report render <sanitized-report.json> \
  --report-sha256 sha256:<exact-report-file-digest> \
  --reconciliation <paired-npm-reconciliation.json> \
  --reconciliation-sha256 sha256:<exact-reconciliation-file-digest>
```

The static report continues to determine `BLOCK`. A separate section presents what the disposable
VM and Codex observed for `CI=false` and `CI=true`. It must not imply payload exfiltration,
authenticated producer provenance, complete telemetry, clean admission, or a newly qualified
malware score.

## Frozen source inputs

Only the already-sanitized local snapshot below is in scope. It is gitignored and must not be
staged:

```text
.whoathere/remote-evidence-snapshots/
  whoathere-actual-malware-2026-07-18-sanitized/npm-sbx-paired/
```

Frozen identities:

| Item | SHA-256 |
| --- | --- |
| Exact artifact | `sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933` |
| Manifest | `sha256:14da51ba0162c2658057202df1e94d71b7a89d5f2a813464830b3eadd06f7f37` |
| P04 sanitized report file | `sha256:bc09a308462940012d9060b54a46ff7568ee94d04a5ccb2d10a3faeca1a5e452` |
| Export manifest file | `sha256:12686a54572505ab36eabd45690919de83cdf13becaf58364c7ced56d4fe0f57` |
| Source reconciliation file | `sha256:e01f4bd4844756bdd5b07a2d3dd111be9283561fad319d3d3be2af7ff852a5c7` |
| Source reconciliation binding | `sha256:bb44a2843b20486d56a8f473d74f283da96187d1d26cdecdc89f233e8c7782f6` |
| Scenario plan | `sha256:4beb163692fa5d6e19822e91dea11b3cf217fe11341f2708221b93459b9c81ca` |
| `CI=false` bundle | `sha256:01c28b2fe0ed53aea0a1886056223e11ffc02f6b528f25fa69ee4cb632d840e8` |
| `CI=true` bundle | `sha256:245f5553dfc4e0e2c4f8029cfdefa12a53452fc922252b3838f06535236f7a81` |
| `CI=false` Codex result file | `sha256:410ee27561e37c00c0c48ce2a04046de4e53c88f33928bc63f55085ad95c522f` |
| `CI=true` Codex result file | `sha256:4ca1d74a169fc71b3c9bc1a3e8f9924a1e69594d7b712aecbc9df363edf0a4cf` |

The provider is `linux_vz_exact_npm_v1`; scenario intent count is exactly two. The two action keys
are exactly `vm_ci_false` and `vm_ci_true`. Each bundle contains exactly 73 typed events and has
incomplete coverage.

## Frozen reconciliation boundary

The existing `whoathere.two_host_behavior_diagnostic.v1` file alone is not accepted as the P05
input. It omits lifecycle, outbound-connect, and network-send findings and cannot independently
re-resolve their citations.

Produce one closed, self-contained
`whoathere.paired_npm_report_reconciliation.v1` envelope from the frozen files. It contains:

- exact artifact, manifest, report, export-manifest, source-reconciliation, scenario-plan, source
  reconciliation-binding, bundle, and Codex-result identities;
- exactly two ordered profile rows, `ci_false` and `ci_true`;
- each complete sanitized `BehaviorAnalysisBundleV1`, with every `untrusted_detail` absent or null;
- a prose-free Codex projection containing exact provider/panel/receipt/correlation identities,
  finding kind, confidence, finding digest, and every event reference;
- explicit incomplete coverage and diagnostic/non-claim-bearing/no-authority safety flags.

The product validator must:

1. verify the envelope's exact detached digest before decoding;
2. enforce a closed schema and bounded regular-file input;
3. decode each embedded bundle through the existing strict bundle decoder and recompute its
   canonical bundle and event identities;
4. require exact artifact, manifest, report, plan, profile, run, bundle, Codex-result, and source
   reconciliation bindings;
5. rederive the source reconciliation input-binding digest from the ordered profile identities;
6. recompute every Codex finding identity and resolve every citation against the matching validated
   bundle event;
7. bind the frozen source identities and complete normalized Codex projection for each profile so
   coherent content changes cannot be authorized by supplying a recomputed envelope digest;
8. accept only the four P05 presentation kinds: lifecycle-trigger execution, credential access,
   outbound connection, and network send;
9. derive all displayed VM/Codex summaries from typed validated content, never from explanation or
   reason strings; and
10. reject missing, duplicate, extra, reordered, mismatched, unsafe, unknown-version, or
   unsupported-field content.

Digest continuity proves integrity under caller-provided custody, not producer authentication. The
sanitized snapshot omits signed root/host receipt bytes, verification keys, provider output, and
raw telemetry. Receipt and provider-output digests are identifiers only.

## Frozen rendered facts

Both profiles must show:

- npm lifecycle execution observed in typed process events;
- credential-file reads observed in typed filesystem events;
- connect and send intent to the local sinkhole as supporting network activity;
- Codex's structurally cited findings, with every citation resolved to a validated event identity;
- incomplete process/filesystem/canary/network/scenario coverage; and
- diagnostic, sanitized, unauthenticated, observe-only, no-admission posture.

The renderer must say that connect/send intent does **not** establish payload or credential
exfiltration. It must not claim a meaningful CI-profile difference merely because two profiles
were run.

The headline and exit code remain the P04 static result:

```text
BLOCK - malicious capability found in package
exit 20
```

The reconciliation may supplement this result but can never create, erase, or downgrade the
static `BLOCK`.

## Allowed work

- One narrow assembler for the frozen sanitized inputs and self-contained envelope.
- One strict runner-owned decoder/validator and presentation view.
- Optional `report render` reconciliation flags and a P05 report section.
- Synthetic focused fixtures and mutation tests.
- One compact sanitized product report and an accurate README update.

## Forbidden work

- No new scorer or evaluation verdict.
- No raw telemetry reinterpretation, new collector, new sensor, new VM run, or hosted Codex run.
- No general multi-provider arbitration, adaptive probes, Claude adapter, or generic evidence graph.
- No clean/admission/sync-back authority.
- No claim that the dynamic evidence is authenticated or claim-bearing.
- No claim of 11/11, R06 completion, broad malware coverage, exfiltration, or CI gating.
- No tracked raw artifact, raw receipt, model prose, canary value, secret, private path, or ignored
  evidence snapshot.

## Frozen acceptance criteria

1. Exact artifact, manifest, report, plan, profile, evidence, Codex-result, source-reconciliation,
   and envelope identities match or rendering fails.
2. Both CI profiles display lifecycle execution and credential-file reads.
3. Connect/send intent is visibly supporting activity and never payload exfiltration.
4. Every displayed Codex citation resolves to the matching strict bundle event and recomputed event
   digest.
5. Incomplete coverage and diagnostic/unauthenticated provenance remain visible; action remains the
   P04 static `BLOCK` with exit 20.
6. Mismatch, coherent citation forgery, omission, duplication, profile substitution/reordering,
   unknown field, unsupported version, and unsafe-authority mutations fail with exit 64 and no
   `BLOCK` or `ALLOW` output.
7. P03 complete-report and P04 sanitized-static rendering remain backward compatible when no
   reconciliation is supplied.
8. Failure output does not echo untrusted content or local paths.
9. No restricted bytes, secrets, model prose, canary values, or ignored snapshot files enter git.

## Required checks

- Focused runner reconciliation validation tests.
- Focused CLI parsing/rendering tests.
- Synthetic positive for both profiles.
- Digest, version, field, identity, profile, omission, duplication, ordering, citation, finding,
  coverage, and authority mutations.
- Existing retained-report runner tests.
- Existing CLI report-render tests.
- Existing exact-artifact spine and development-baseline self-tests.
- Workspace formatting, clippy, and tests.
- Production render of the frozen local sanitized npm inputs.
- Independent Ultra verification after implementation, before commit or push.

## Stop and parking rule

If the self-contained envelope cannot be made strict without changing the upstream bundle or Codex
schemas, park the exact missing binding and stop. Do not weaken citation resolution, trust producer
reason strings, or expand into a generalized protocol. P06 remains queued until P05 is either
accepted or explicitly parked with a reproducible blocker.

## Completion result

```text
Chunk: P05
Start SHA / implementation SHA: 96aae35 / 84f24f6
Active time used: within the 2-4 hour focused implementation budget; independent verification was
  performed separately
User-visible outcome: whoathere report render supplements the existing npm static BLOCK with
  separately labeled CI=false and CI=true disposable-VM/Codex evidence while preserving exact
  citations, incomplete coverage, and no-authority posture
Command or report: whoathere report render <report> --report-sha256 <digest> --reconciliation
  <envelope> --reconciliation-sha256 <digest>; paired-npm-vm-codex-product-report.md
Representative input: frozen sanitized npm report bc09a308...e452 plus reconciliation envelope
  ac521c94...52b5
Paired controls: P03 complete report and P04 sanitized static report without reconciliation;
  baseline plus 18 fail-closed P05 mutations
Acceptance criteria passed: 9/9 after the independent verifier's coherent identity/citation
  substitution finding was fixed and independently rerun
Acceptance criteria not passed: none
Diagnostic detection score: unchanged diagnostic prior-miss result 4/4; finalized July experimental
  baseline remains 7/11
Claim-bearing detection subscore: not produced; P05 evidence is explicitly unauthenticated and
  diagnostic-only
Completion/quality gate: incomplete in process, filesystem, canary, network, and scenario coverage
Overall evaluation passed: false / not an evaluation campaign
Safety invariants: host package execution zero; sync-back zero; unsafe allow/admission zero;
  restricted-material leak zero; live-C2 contact zero; live second-stage fetch zero; invalid or
  unverified teardown zero/not applicable because P05 opened no artifact and started no VM. Evidence:
  saved-report product selftest, independent verifier, ignored-snapshot and staged-file audit.
One parked blocker: producer authentication is unavailable in the sanitized snapshot and remains
  visibly deferred to the later claim-bearing R05 path
Recommended next chunk: P06 cloud-lab ready/not-ready preflight, with no artifact access or VM start
```

The full workspace test suite, formatting, clippy with warnings denied, the deterministic assembler,
the production render, and the focused baseline-plus-18 mutation suite passed. Independent Ultra
verification returned GO after confirming that coherent citation omission, source-reconciliation
substitution, and observer-result rebinding now fail with exit 64 and no `BLOCK`, `ALLOW`, or path
leak. The exact valid report remains the P04 static `BLOCK` plus the supplemental dynamic section.
