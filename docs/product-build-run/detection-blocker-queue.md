# Detection Blocker and Revisit Queue

Date opened: 2026-07-15

This queue records bounded work that stopped without reaching its physical or claim-bearing gate.
An entry must distinguish confirmed evidence from inference, preserve the safety boundary, and name
the smallest decision or experiment needed to resume it. Mainline work moves to another
detection-bearing slice instead of continuing an unbounded patch loop.

## BLK-001: resolved -- physical npm evidence sealing stopped on guest sensor control I/O

Status: resolved on July 16, 2026. It no longer blocks npm or wheel execution.

Resolution evidence:

- the diagnostic runtime and host helper changes were rebuilt, re-signed, and requalified;
- the same exact inert npm tarball completed physically under both `ci_false` and `ci_true`;
- `ci_false` did not activate protected-canary or network behavior by design, while `ci_true`
  produced authenticated protected npm-token open/read observations and a fixed loopback TCP
  connect that reached typed projection;
- the physical `packaging` wheel and all eight actions of the trigger-rich wheel also completed,
  demonstrating that the former fault no longer blocks the shared npm/wheel execution path;
- verified VM stop, clone destruction, no public route, and no sync-back held.

Evidence coverage remained honestly incomplete. Resolving BLK-001 did not establish independent
guest-root or host-composite completeness, clean eligibility, or admission eligibility.

No resume experiment is required. Preserve the completed inert npm and wheel runs as regression
fixtures; reopen this entry only if the same sensor-control failure recurs on those pinned inputs.

## BLK-002: the signed event denominator and independent verifier do not exist

Status: parked after independent audit. The strict evaluator remains fail-closed, and production
registry generation remains `not_generated`. The uncommitted Python producer prototype is not
claim-bearing and must not be released as an independent verifier path.

Confirmed:

- the prototype sent producer-authored `RunResultV2` observations and labels to its verifier, so a
  verifier could merely echo the claimed detections;
- exhaustiveness was measured against that producer-authored observation list, not against every
  event committed by signed receipts;
- the current work has no production native verifier executable;
- a verifier cannot prove omitted events unless expected bindings, host composition, root receipts,
  modality receipts, and streams commit to a complete ordered event denominator;
- therefore a signed registry produced by the prototype would not make an 11/11 score trustworthy.

Required v2 boundary:

- the verifier request contains only frozen evaluation/run-slot identities and opaque, digest-bound
  structural evidence sources; it contains no result, verdict, observation IDs, evidence types,
  behavior labels, evidence references, or expected detection facts;
- trusted expected bindings commit to the complete scenario/action set; the host-composite receipt
  commits to every ordered action/root receipt; each root or modality receipt commits to every
  stream's schema, length, digest, event count, and ordered event manifest or Merkle root;
- a native, measured, side-effect-free verifier independently authenticates that receipt graph,
  enumerates every committed event, and derives typed projections only from allowlisted primitive
  event fields;
- every authenticated event is assigned exactly one disposition: projected, recognized
  non-observation, unsupported schema, or malformed signed event; unsupported or malformed events
  preserve valid sibling positives but force incomplete coverage and can never support clean;
- only after the verifier exits does the producer compare its independently derived run fact and
  complete projection set bidirectionally with `RunResultV2`;
- any missing action, receipt, stream, frame, event, projection, denominator commitment, or identity
  match prevents registry generation.

The July 16 npm run does not close this blocker. Authenticated positive events can be projected and
reviewed, but the physical bundle still lacks a complete independently verified event denominator
and complete modality coverage. Such observations remain useful for manual review; they cannot
make an incomplete row detection-recall eligible or support clean admission.

Smallest resume experiment:

1. Define an inert signed receipt chain for one action with two ordered primitive events: one file
   read that projects to a typed observation and one recognized non-observation.
2. Have a native verifier derive both event IDs, the exact partition, and the one projection without
   receiving any producer observation or label.
3. Prove that omitting either event, inventing or relabeling a projection, changing an ordinal,
   replaying another run, or substituting a source prevents registry generation.
4. Prove that an unsupported third signed event preserves the positive projection but changes
   coverage to incomplete and keeps `observed_clean` impossible.
5. Only then reconnect the Python registry publisher and its off-tree signing helper.

Until the receipt chain supplies that denominator and the native verifier passes this inert fixture,
no new campaign can produce a claim-bearing verified registry.

## BLK-003: the physical host harness discards partial evidence and overstates failure state

Status: partially superseded by successful physical npm and wheel runs. The remaining concern is
limited to retaining and accurately reporting partial evidence on failed execution paths.

Confirmed:

- the guest emits a partial result and child diagnostic log when package execution fails, but the
  serial parser rejects the failure marker before parsing either artifact;
- the physical command requires a terminal `complete` result, so a structurally valid
  `process_failed` result and its typed Rust failure are reduced to a generic host error;
- any retained network frame is treated as harness failure before it is retained as behavioral
  evidence;
- the helper still requires the fixture-only `malware_execution=false` marker;
- its generic error output always reports package and malware execution as false, even after a VM
  may have started or executed, and does not report whether stop and clone destruction were proven;
- success-path teardown waits for verified stop and clone identity before destruction, but the
  failure path cannot make the same claim.

Required correction:

- parse and retain every structurally valid partial result, child log, and signed evidence frame
  before classifying the terminal status;
- treat failed package processes and retained network frames as behavioral evidence, not automatic
  harness failure;
- replace fixture markers and booleans with separate attempt, execution-observed, completion,
  VM-stop, clone-destruction or preservation, and evidence-coverage states;
- preserve a clone on stop-unproven failure and never report destruction without re-verification;
- independently verify each root receipt and host-composite receipt before projecting typed
  observations;
- keep any incomplete or unverified coverage incapable of producing observed-clean.

Smallest resume experiment:

1. Run an inert fixture that writes one marker, emits one retained sinkhole-bound network frame, and
   exits nonzero with a typed child failure after a valid partial result.
2. Require the host result to preserve the marker, frame, process failure, child reason, action
   index, and honest incomplete coverage without treating any of them as harness corruption.
3. Exercise timeout, verified-stop failure, and stop-unproven failure separately; require exact
   attempt/execution/stop/clone states and preserve the clone whenever stop is not proven.
4. Reject duplicate or out-of-order serial markers, mismatched action indexes, forged completion,
   omitted frames, and receipt rebindings.
5. Preserve these as failure-path hardening gates; they do not invalidate the successful npm and
   wheel physical runs recorded under resolved BLK-001.

## BLK-004: one static Codex specialist still misses an inert credential-exfiltration flow

Status: parked so it does not delay the dynamic vertical.

On July 15, 2026, the exact-artifact adapter selected the `CredentialFilesystem` specialist for
reachable npm postinstall JavaScript that reads `HOME/.npmrc`, encodes it, and attempts a DNS lookup.
The deterministic analyzer produced behavior findings, but the measured subscription-backed Codex
invocation returned no finding. The result remained correctly inconclusive and had no admission
authority.

Do not spend the current working-solution slice tuning prompts around this one fixture. Codex has
now consumed bounded physical process, file, network, and canary observations from disposable-VM
runs. Revisit static prompt/pass design afterward using multiple hidden positive and benign
controls.

On July 16, the observe-only dynamic Codex panel cited authenticated protected npm-token reads and
a loopback TCP connect from a physical behavior bundle while correctly refusing to infer
exfiltration. This proves the dynamic telemetry-review path; it does not resolve the static-review
miss or the evidence-completion blocker.

## BLK-005: resolved -- empty-closure sdist runtime failed before VM boot

Status: resolved on July 16, 2026. The base physical PEP 517 sdist path is no longer blocked.

The failure had two demonstrated causes:

- the initramfs builder used `jq -er` to extract a valid
  `build_closure_payload_present: false` value, so `jq` status semantics combined with `set -e`
  terminated the builder;
- the root runtime required a build-closure payload for every `ValidateExactBuildClosure` action,
  even when the declared closure contained no artifacts.

The builder now type-checks the field before extracting it without `-e`, and the root runtime now
requires a payload descriptor only for a nonempty closure artifact list. A regression test covers
both empty and populated closures. The rebuilt runtime was offline-verified and physically
requalified before reuse.

The exact nested-root PEP 517 inert sdist then completed all four physical actions in fresh,
disposable guests:

- build: behavior bundle
  `sha256:a40f43ec34fc8ae61460f35c3be70976b18d13ddf2906bdd86e69af20c387ab7`
  with one event;
- derived-wheel inspection:
  `sha256:8927046deb0ac6a0981c226b2fef49b92180b52d0179e6488a5a2b36d2161095`
  with one event;
- derived-wheel install:
  `sha256:4835b554a6d824e0d0a91828d47c6e24bb0e91ec40f45d9c4cdbb549b16d238c`
  with eight events;
- import root:
  `sha256:d37032e43d196729fc3a71d686adc513b8cecd7b571a74becbb30670da9c222b`
  with one event.

Verified teardown, no public route, and no sync-back held. Codex subsequently consumed the
authenticated install-action bundle and returned a receipt-bound no-finding result that remained
correctly inconclusive and had no admission authority.

This result proves the base four-action physical PEP 517 path, not complete sdist trigger coverage,
clean admission, legacy or ZIP support, or malware detection. The product still reports
`derived_wheel_probe_manifest_required`, `sdist_build_closure_required`, and
`dynamic_build_requirements_possible`. Preserve this fixture as a regression; no BLK-005 resume
experiment remains.
