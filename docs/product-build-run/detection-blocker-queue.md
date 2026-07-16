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

## BLK-002: independent receipt/event verifier executable does not exist

Status: contract and fail-closed registry producer implemented; production registry remains
`not_generated`.

The evaluator requires an independently signed verified-evidence registry. The producer now
enforces the frozen denominator, exact evidence mappings, an operator-pinned verifier executable,
an existing off-tree Ed25519 key, exclusive output publication, and verify-only validation. It does
not invent authentication when the verifier is absent.

Resume requirement:

- implement a side-effect-free Rust `whoathere-package-evidence-verify` executable for the closed
  `whoathere-independent-receipt-event-verifier-v1` protocol;
- reconstruct every host-supplied expected binding;
- verify guest-root and host-composite signatures plus every typed event projection;
- emit only the canonical non-authorizing response;
- keep authenticated zero-frame evidence and complete host composition as prerequisites.

Until that executable and the missing physical receipt bindings exist, no new campaign can produce
a claim-bearing verified registry.
