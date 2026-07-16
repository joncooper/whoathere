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
- exact inert npm runs completed physically under both `ci_false` and `ci_true`;
- authenticated process, file, canary, and network evidence reached typed projection;
- the physical `packaging` wheel and all eight actions of the trigger-rich wheel also completed,
  demonstrating that the former fault no longer blocks the shared npm/wheel execution path;
- verified VM stop, clone destruction, no public route, and no sync-back held.

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

Do not spend the current working-solution slice tuning prompts around this one fixture. First feed
Codex the actual bounded process, file, network, and canary observations from a disposable-VM run.
Revisit static prompt/pass design afterward using multiple hidden positive and benign controls.

## BLK-005: sdist helper fails in the execution-image subprocess before VM boot

Status: parked after repeated physical reproduction on July 16, 2026. npm and wheel work proceeds
independently; this is the only current blocker to the first physical PEP 517 sdist run.

Confirmed:

- the exact-sdist adapter and CLI dispatch are implemented;
- the nested-root PEP 517 fixture normalizes and reaches its digest-bound signed execution bundle;
- the host helper repeatedly fails closed while launching the execution-image subprocess, before
  the disposable VM boots or package code executes;
- the exact execution-image builder succeeds when invoked manually on the cloud Mac;
- no sdist behavior bundle was accepted, no sync-back occurred, and this is not a physical sdist
  detection claim.

Not established:

- the relevant difference between the helper-launched subprocess and the successful manual image
  build has not been isolated.

Smallest resume experiment:

1. Capture a bounded, sanitized record of the helper's builder executable identity, arguments,
   working directory, environment allowlist, exit status or signal, and stderr.
2. Replay that exact invocation manually under the same cloud-Mac user and working directory, then
   compare it with the already successful manual build.
3. Correct only the first demonstrated launch, environment, path, or I/O difference; rebuild and
   sign the helper once.
4. Rerun the same fixture and require VM boot plus authenticated build, derived-wheel inspection,
   install, and import action bundles, while retaining incomplete coverage, verified teardown, no
   public route, and no sync-back.
