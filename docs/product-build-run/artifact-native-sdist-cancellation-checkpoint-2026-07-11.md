# Artifact-Native sdist Cancellation Checkpoint

Date: 2026-07-11

Status: the authority-first sdist helper now handles `SIGINT` and `SIGTERM` through an
interruptible, fail-closed cancellation path; unit and inert CLI checks pass, while live VZ
teardown qualification remains open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Helper VZ Route Checkpoint](artifact-native-sdist-helper-vz-route-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Supervisor Provisioning Checkpoint](artifact-native-sdist-supervisor-provisioning-checkpoint-2026-07-11.md)

## Outcome

The sdist route no longer inherits the process-default interruption behavior while it may own a
submission, listener, VM, guest session, or disposable clone. A first-writer-wins cancellation
latch records either:

- `sdist_run_cancelled_by_sigint`; or
- `sdist_run_cancelled_by_sigterm`.

Signal handlers only set that latch. They do not call `exit`, delete a clone, or directly mutate VM
state. The normal orchestration path observes cancellation and performs listener removal, VM stop,
guest-session termination checking, and clone disposition in order.

After listener removal has serialized with the VM queue, the route distinguishes “no guest
connection was ever accepted” from “an accepted session has not returned.” The first is positive
proof that no guest channel exists and permits cleanup after a proven VM stop; the second retains
the clone.

## Cancellation boundaries

Cancellation is checked:

1. before submission intake;
2. while waiting for submission prefix, header, artifact body, and final EOF;
3. after authority consumption and before measured-base verification;
4. before and after disposable-clone creation;
5. before a VM start is enqueued and while waiting for its completion;
6. while waiting for the authenticated guest staging session; and
7. after guest-session evidence is returned but before success can be emitted.

The exact-byte input reader uses bounded `poll` intervals only when a cancellation state is
supplied. Existing non-production parser callers retain their prior blocking API by default.

If cancellation occurs after a VM start is in flight, the helper removes the sdist VSOCK listener,
requests graceful VM stop, attempts the existing bounded force-stop fallback, and then waits for the
accepted guest channel to terminate. The clone is deleted only when both VM stop and guest-session
termination are proven. Otherwise the clone is retained with the existing explicit fail-closed
reason code.

## Evidence fields

Both pre-VM and post-start error envelopes now report:

- `cancellation_requested`;
- `cancellation_reason`;
- authority-consumption and replay-state status;
- clone-cleanup status; and
- immutable `package_execution_enabled=false`, `sync_back_enabled=false`, and
  `build_closure_materialized=false` values.

A successful non-executing staging result explicitly reports no cancellation.

## Verification

The focused cancellation suite proves:

- first-writer-wins signal attribution;
- ordinary completion;
- bounded cancellation of completion waits;
- fail-closed timeout;
- cancellation of a blocked submission read before authority or VM activity; and
- no accidental completion-semaphore consumption by cancellation.

The existing terminal-policy test separately proves that a clone is retained when either VM stop
or guest-session termination is unproven.

An inert CLI check started the debug helper with a syntactically valid fake authority id and digest,
provided no submission bytes, and sent terminal `Ctrl-C`. The helper exited without creating or
starting a VM and emitted:

- `authority_consumed=false`;
- `cancellation_requested=true`;
- `cancellation_reason=sdist_run_cancelled_by_sigint`;
- `clone_cleanup_succeeded=true`; and
- all package execution, sync-back, and build-closure materialization fields false.

The full Swift suite and release build pass. No VM, package manager, build backend, network,
restricted sample, or malware was used.

## Claim boundary and next gate

This checkpoint proves process-local cancellation routing and the pure clone-retention policy. It
does not yet prove a live Virtualization.framework guest stops under `SIGINT` or `SIGTERM`, that a
blocked VSOCK writer terminates after VM stop, or that the provisioned sdist supervisor produces the
expected authenticated staging receipt in a live boot.

Those claims require a provisioned, measured stopped base and one inert live VZ staging run on an
independently confirmed Mac. The cloud Mac remains ineligible until its changed SSH host identity is
confirmed. Real-malware execution remains separately gated and unauthorized by this checkpoint.
