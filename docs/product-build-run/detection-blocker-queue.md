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

## BLK-002: one-action native denominator proved; complete verifier wiring remains

Status: partially resolved on July 16, 2026. A bounded native proof now independently verifies and
partitions one action's signed file-event stream. The strict evaluator remains fail-closed,
production registry generation remains `not_generated`, and the uncommitted Python producer
prototype is not claim-bearing or releasable as an independent verifier path.

Confirmed:

- the prototype sent producer-authored `RunResultV2` observations and labels to its verifier, so a
  verifier could merely echo the claimed detections;
- exhaustiveness was measured against that producer-authored observation list, not against every
  event committed by signed receipts;
- the current work has no production native verifier executable;
- a verifier cannot prove omitted events unless expected bindings, host composition, root receipts,
  modality receipts, and streams commit to a complete ordered event denominator;
- therefore a signed registry produced by the prototype would not make an 11/11 score trustworthy.

Completed bounded proof:

- verified root-receipt tokens now expose their signed process-plan, action-index, file-length, and
  file-event-count commitments;
- a native Rust partitioner consumes only trusted expected bindings, independently verified root
  and host receipt tokens, and decoded receipt-bound file evidence--never a producer result,
  observation, behavior label, reason string, or verdict;
- one inert two-event fixture derives a typed sensitive-SSH-read projection and exactly accounts
  for an ordinary workspace open as a recognized non-observation;
- an authenticated unsupported sibling remains in the denominator, preserves the positive
  projection, forces projection coverage incomplete, and cannot enable `observed_clean`;
- omission, ordinal mutation, signature/key failure, artifact/grant/root/host/file replay or
  substitution, and serialized-output tampering fail; generation and verification share the
  existing 256 MiB runtime-result ceiling;
- all seven focused tests, all 269 `whoathere-macos-vm` tests, formatting, strict Clippy, and an
  independent bounded review pass.

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

The July 16 npm, wheel, and sdist runs do not close this blocker. Authenticated positive events can
be projected and reviewed, but the physical bundles still lack a complete independently verified
event denominator and complete modality coverage. Such observations remain useful for manual
review; they cannot make an incomplete row detection-recall eligible or support clean admission.

Remaining claim-bearing boundary:

1. Extend host composition from one root receipt to the complete ordered action/root set and apply
   the same denominator rule to every required process, file, canary, and network stream.
2. Define the honest trusted-input contract needed by a standalone native verifier executable;
   root-receipt verification currently requires caller-supplied claims, so a thin file-only CLI
   would invent authority.
3. Compare the independently reconstructed projection set bidirectionally with `RunResultV2`, then
   reconnect the registry publisher and off-tree signing helper.

The inert native proof closes the smallest experiment, but current physical bundles still lack the
complete multi-action, multimodality denominator. New cloud-lab slices may produce useful positive
manual-review evidence, but no campaign can produce a claim-bearing verified registry until the
remaining boundary is complete.

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

The separate canary-bearing sdist run recorded under BLK-006 does not reopen the resolved
empty-closure defect.

## BLK-006: canary-bearing sdist action 3 completed in the guest but did not project

Status: ready for one bounded physical confirmation. It does not block the completed wheel proof or
the projected sdist build-backend evidence from actions 0 through 2.

Confirmed:

- the current signed helper,
  `sha256:d2a0785c6c6a37988e7c61a1870a5152e3a9e3e9b295986a734f0e1eab4123a1`, restores
  `selected_process_stage_name` and was used for this run;
- one exact inert canary-bearing sdist completed guest actions 0 through 2 and projected typed
  behavior bundles;
- action 0 projected build-backend activation, protected PyPI-token canary access, and fixed
  local-sinkhole network intent; observe-only Codex detected all three while preserving incomplete
  coverage and making no canary-exfiltration claim;
- action 3 completed in the guest, but the host failed before projecting the 5,945,958-byte runtime
  result;
- independent guest-root and host-composition completeness remain unmet, so no result is
  `observed_clean`, admission-eligible, or complete for detection recall.

On July 17, the later large-evidence correction was tested directly against the retained result
size. A synthetic, structurally valid `5,945,958`-byte root-runtime result crossed both Mac host
boundaries: the base64 serial extractor and the `WTPKRR01` root-runtime frame parser. Its selected
action index was `3`, its process-evidence frame was larger than the former 4 MiB ceiling, and the
current 16 MiB per-modality ceiling preserved it exactly. A companion boundary test rejected a
frame one byte above 16 MiB. Existing Rust tests already cover the same raised frame and
sensor-control limits.

This strongly indicates that commit `33cdf41` incidentally removed the bounded host-size failure
while fixing the later Telnyx-neighbor evidence path. It does not prove which modality in the
original retained result crossed 4 MiB, and it does not replace a fresh physical action-3 run.

Smallest resume experiment:

1. Reproduce only action 3 with the same pinned inert artifact, current helper/runtime, and
   scenario.
2. Require the complete declared `5,945,958`-byte-class result to cross serial parsing, root-runtime
   parsing, evidence-file retention, and typed projection.
3. Require the existing VM-stop, clone-destruction, no-public-route, and no-sync-back invariants.

Until that physical confirmation runs, preserve actions 0 through 2 as valid positive evidence and
report the full sdist run as incomplete.

## BLK-007: resolved -- Telnyx wheel evidence capacity and serial transport

Status: resolved on July 17, 2026. The public Telnyx neighbor no longer blocks the two approved
known-miss wheel experiments.

Resolution evidence:

- fixed stage-specific failure codes replaced the broad sensor-control collapse without exposing
  raw telemetry;
- the exact Telnyx `4.87.0` install produced 5,108,950 bytes of authenticated process evidence and
  4,198,077 bytes of file evidence, proving that the former 4 MiB limit—not the artifact format—was
  the first failure;
- the enforcing Rust and Swift evidence contracts now share a 16 MiB per-modality limit, and the
  rebuilt runtime passed offline verification and fresh physical qualification;
- a fresh install action then completed successfully with complete declared payload lengths and
  digests;
- the import action exposed a second bounded transport defect: kernel messages at `loglevel=6`
  could interleave inside the large base64 result on the shared serial console, producing an honest
  `lengthMismatch`;
- the guest now keeps normal kernel logging during package execution, switches the kernel console
  to emergency-only only for evidence transfer, verifies that transition, and fails closed if the
  transition or drain cannot be established;
- a fresh import action then parsed the complete result and preserved the nonzero package-process
  outcome as evidence. Its nonzero result reflects the intentionally absent dependency closure and
  remains inconclusive rather than clean;
- the offline wheel projector revalidated the exact wheel, envelope, manifest, scenario, receipts,
  and modality digests and produced private behavior bundles for both actions. Observe-only Codex
  returned no finding for the install and cited the typed wheel-import event as context-only
  lifecycle execution for the import action;
- both physical runs stopped the VM, destroyed its clone, retained stable image identity, exposed
  no public route, and performed no sync-back. Neither bundle has independent host composition,
  observed-clean status, or admission authority.

No BLK-007 resume experiment remains. Preserve the exact neighbor actions, the over-4-MiB boundary
tests, the serial-init self-test, and the offline projection commands as regressions. A dedicated
evidence console is optional later hardening, not a prerequisite for the known-miss wheel runs.
