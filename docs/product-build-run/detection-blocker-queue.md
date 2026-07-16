# Detection Blocker and Revisit Queue

Date opened: 2026-07-15

This queue records bounded work that stopped without reaching its physical or claim-bearing gate.
An entry must distinguish confirmed evidence from inference, preserve the safety boundary, and name
the smallest decision or experiment needed to resume it. Mainline work moves to another
detection-bearing slice instead of continuing an unbounded patch loop.

## BLK-001: npm CI=true process evidence stops on an orphan `sendto` exit

Status: paused after the runtime-v11 decision run; no runtime-v12 work authorized.

Confirmed:

- deterministic runtime qualification passed twice and the signed qualification record verified;
- the exact inert npm artifact and sealed CI=true template failed closed before an accepted package
  result;
- the bounded child reason was `exit_without_enter`, observed syscall `sendto`, pending count zero;
- the failure propagated as process-stream pairing invalid, then process-sensor runtime fault;
- the VM stopped, the disposable clone was destroyed, no public route or sync-back existed, and
  CI=false was not run.

Not established:

- CPU migration or single-CPU tracepoint attachment is not the cause; prior physical qualification
  disproves that hypothesis for this backend;
- an unsupported, null, non-IP, or unreadable `sendto` address being discarded on entry while its
  exit is retained is plausible from the producer code, but the v11 evidence does not prove it.

Recommended resume decision:

- replace online syscall-pair completeness with a bounded guest-local `ActionEvidenceBundleV1`;
- journal structurally valid syscall halves, process lifecycle, file/canary, and cgroup-egress facts;
- derive pairing and correlations after the action, without allowing a missing half to erase valid
  evidence or abort sealing;
- sign the ordered journal, coverage counters, and typed gaps, then bind it to host raw-frame,
  teardown, and clone-destruction evidence;
- forbid `observed_clean` for any orphan half, producer drop, unsupported target detail,
  truncation, missing modality, or failed host composition.

First experiment on resume:

1. Exercise `exec -> orphan sendto exit -> file/canary event -> cgroup egress -> leader exit`.
2. Require a valid signed bundle with one typed `unpaired_syscall_exit/sendto` gap and all valid
   positive observations preserved.
3. Prove that omitted gaps, forged completeness, count changes, or bundle tampering fail
   verification.
4. Rebuild deterministically, requalify twice, and rerun only the same CI=true inert artifact.
5. Keep CI=false held until the CI=true result has authenticated guest evidence, independently
   verified host composition, honest incomplete/non-clean status, and complete teardown.

Alternatives considered:

- retaining the current stream and merely signing typed gaps is slightly faster but preserves the
  brittle online-pair invariant and its adjacency assumptions;
- dropping syscall-intent evidence for an alpha run is faster but loses failed/pre-transmission
  network intent, credential transitions, and dynamic-loading evidence, and could never support an
  observed-clean result.

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
