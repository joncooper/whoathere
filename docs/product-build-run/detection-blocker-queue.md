# Detection Blocker and Revisit Queue

Date opened: 2026-07-15

This queue records bounded work that stopped without reaching its physical or claim-bearing gate.
An entry must distinguish confirmed evidence from inference, preserve the safety boundary, and name
the smallest decision or experiment needed to resume it. Mainline work moves to another
detection-bearing slice instead of continuing an unbounded patch loop.

## BLK-001: physical npm evidence sealing stops on guest sensor control I/O

Status: paused after physical reproduction with the current qualified generic execution stack.
Static exact-artifact work can proceed independently, but physical behavioral observation cannot
claim success until this boundary emits an authenticated bundle.

Confirmed:

- the earlier targetless-`sendto` and execution-window fixes were rebuilt and qualified;
- exact inert npm runs now fail at the root runtime with
  `linux_vz_package_sensor_control_io_failed`, before authenticated evidence sealing;
- both a lifecycle-only fixture and a canary-read fixture reproduce the same failure, so
  package-authored networking is not required;
- matching the current generic helper, runtime, and image stack does not remove the failure, so it
  is not explained by the older helper/parser mismatch;
- the VM stops safely, the disposable clone is destroyed, no sync-back occurs, and no behavior
  bundle is accepted.

Not established:

- the exact control operation and guest component that fails have not yet been isolated;
- no physical behavior bundle has reached the Codex observer, so the successful inert static-AI
  result is not a physical detonation-observation claim.

Smallest resume experiment:

1. Add bounded stage and error reporting around the existing sensor-control exchange.
2. Rerun the lifecycle-only fixture under `ci_false` and fix the first identified control failure.
3. Require authenticated process, file, canary, and network evidence with honest coverage plus
   verified stop, clone destruction, and no sync-back.
4. Only then repeat `ci_true` and pass the resulting bundle to the Codex behavioral observer.

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

Status: parked after read-only audit. The Rust/C v7-v11 diagnostic core is a useful fail-closed
checkpoint; the untracked Swift physical helper remains inert-only and non-authoritative.

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
5. Only after these inert cases pass may the physical helper be attached to real-package
   acceptance; this does not resume BLK-001's online syscall-pair redesign.

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
