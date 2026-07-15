# Multi-action protected sensor-session checkpoint

Date: 2026-07-15

Status: verified code-and-protocol checkpoint; measured guest-service custody, an
execution-capable package runtime, and physical artifact qualification remain open

## Result

The Linux VZ package sequencer can now keep one protected root-sensor session open across every
ordered process action in an npm, wheel, or sdist plan. This closes a prerequisite discovered while
preparing physical inert-package qualification: npm currently has one process action, while wheel
and sdist plans require multiple actions, but the protected service previously terminated after the
first per-action finish acknowledgement.

Each process action still has a distinct cgroup, launch contract, terminal result, canonical root
process/file/network evidence set, and authenticated incomplete root-evidence receipt. After a
successful per-action finish, the collector returns to a bounded ready state instead of terminating
the control session. A later arm is accepted only when:

- the action index is nonzero, strictly greater than every completed process-action index, and
  within the 64-action session limit;
- the process-plan digest is identical to the digest locked by the first action;
- no prior action remains active; and
- the existing exact cgroup-name, launch-contract, descriptor, sensor-health, and no-route/no-sync
  checks pass.

The service and observer independently retain the ordered indexes of actions whose authenticated
finish-v4 result was accepted. Neither side derives that list from a caller-supplied count.

## Explicit completion handshake

A new `complete_session` / `complete_session_ack` exchange closes the session only after at least one
process action has completed. The request and acknowledgement bind:

- the exact sensor-session identity and challenge;
- the one locked process-plan digest;
- an exact, nonempty, strictly increasing completed-action list and count; and
- the continued requirement for independently verified host composition.

The service accepts completion only when its internally retained list exactly matches the request,
no action or descriptor remains active, and the collector has no live per-action process or file
collector. The acknowledgement additionally requires protected sensor teardown. Both canonical
wires fix `evidence_complete`, `authoritative_verdict_permitted`, public routing, and `sync_back` to
false. Completion therefore authenticates session closure; it is not an observed-clean statement,
a malicious/safe verdict, or copy-back authority.

The execution sequencer now withholds its transcript until artifact, closure, and workspace cleanup
succeed and the observer verifies the exact completion acknowledgement. Reordered, duplicated,
empty, cross-plan, prematurely completed, or policy-upgraded sessions fail closed. If a later action,
cleanup step, control message, or sensor operation fails, the existing abort path remains responsible
for terminating the session without returning a successful transcript.

## Verification

Completed locally:

- macOS `whoathere-macos-vm` library tests: 233 passed;
- Linux/aarch64-musl guest-target test compilation: passed;
- full Rust workspace tests and documentation tests: passed;
- native workspace and Linux/aarch64-musl target Clippy with warnings denied: passed;
- macOS VM Swift helper: 218 passed;
- Rust formatting and diff whitespace checks: passed;
- completion-contract tests cover exact canonical request/acknowledgement decoding, distinct frame
  kinds, ordered indexes, and rejection of empty, duplicate, reordered, wrong-count, clean,
  verdict-authorizing, sync-back, unauthenticated, or incomplete-teardown claims;
- all preceding finish-v4 receipt, one-use signer, grant binding, sensor correlation, cleanup, and
  no-sync tests remain green.

The approved cloud Mac was inventoried through its configured SSH key. The expected inert July 14
source/artifact area and available capacity were present. This was read-only preparation: no VM was
launched, no package was transferred or executed, and no restricted malware material was accessed.

## Claim boundary

This checkpoint does not claim:

- a measured guest process exclusively owns the root service or signing seed;
- the existing nonexecuting package-runtime candidate can execute npm, wheel, or sdist plans;
- a physical multi-action sensor session has run under Virtualization.framework;
- an inert npm, wheel, or sdist has been physically qualified;
- complete host-frame, DNS, HTTP(S), IPv6, TCP, GSO, retransmission, or global file coverage;
- an authoritative clean or malicious verdict;
- any sync-back authority; or
- improved malicious-package detection coverage.

No VM, package, or malware was run for this checkpoint. The July 1 actual-malware result therefore
remains 7 of 11 behavior detections (63.6%); containment remained successful, while the detection
gate remains open.

## Next gate

Build and measure the dedicated guest service process that exclusively owns the one-use signing
authority, and produce an execution-capable package runtime whose fixed runner can enact the already
typed npm, wheel, and sdist process plans without accepting free-form commands. Rebuild and preflight
that composition reproducibly. Only then run the inert npm, wheel, and nested-root sdist scenarios
on the approved cloud Mac, requiring an authenticated incomplete receipt for every process action,
the exact session-completion acknowledgement, independently verified host evidence, stopped VM,
destroyed clone, no public route, no verdict upgrade, and no sync-back. Real-malware execution still
requires the separate restricted-lab approval gate.
