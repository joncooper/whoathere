# Artifact-Native Linux VZ Package-Sensor Terminal-Reconciliation Checkpoint

Date: 2026-07-14

Status: exact supervisor/kernel terminal-reconciliation contract implemented and fail-closed; real
root-collector integration remains open

## Outcome

The protected package finish path now has one exact representation for the root supervisor's raw
Linux wait status and one mandatory, independently sourced kernel wait status in correlation
evidence. Correlation is accepted only when:

1. the supervisor's raw wait status is exactly consistent with its typed exit or signal result;
2. the finish request and acknowledgement echo that exact supervisor status;
3. correlation binds the exact status expected by the supervisor; and
4. the independently observed kernel status equals the supervisor status exactly.

This closes the wire, state, and verification contract that the production root collector must
satisfy. It prevents two individually well-formed but inconsistent terminal stories from being
accepted.

It does **not** instantiate the production root collector. The existing collector boundary still
has no production implementation that owns the BPF producer, consumes the ring buffer, and derives
the kernel status from the final cgroup-bound exit event. Current correlation fixtures provide both
values only to exercise the strict contract. The July malicious-package result therefore remains
**7/11 (63.6%)**, below the 85-90% gate.

## Safety boundary

No VM, package, or malware sample ran for this checkpoint. Validation used Rust unit/integration
tests, canonical inert fixtures, cross-compilation, and an offline static link.

Real malware remains cloud-Mac-only and may run only inside a fresh disposable Linux VZ guest under
the separate restricted-lab workflow. It must never run in this workspace, in Docker, or on either
Mac host. Sync-back remains structurally unavailable for unknown or malicious-package work.

## Exact wait-status model

`LinuxVzPackageProcessCompletionV1` now retains `supervisor_wait_status: u16` in addition to the
normalized terminal fields. Construction fails unless the raw and typed forms are exactly
consistent:

- an ordinary exit requires `wait_status == exit_status << 8`;
- a signal termination requires a zero high byte and the low seven bits to equal signal `1..=64`;
- the signal core-dump bit is preserved rather than normalized away; and
- stopped, continued, malformed, mistyped, and cross-terminal encodings are rejected.

The Linux supervisor converts its exact `waitpid` result to the bounded raw representation only
after `WIFEXITED` or `WIFSIGNALED` succeeds. Tests bind exit status `7` to raw status `0x0700` and
signal `11` with the core bit to raw status `0x008b`.

## Protected control v3

Finish request and acknowledgement schemas advance from v2 to v3. Both require
`leader_supervisor_wait_status` as a minimally encoded unsigned decimal `u16`. The protected
service reconstructs the completion from the raw and typed fields, so a sender cannot provide a
valid exit code with a contradictory wait status. The acknowledgement echoes the same exact value
and is compared byte-semantically by the observer.

The v1 and v2 schema constants remain as historical identifiers, but the active observer and
service accept only v3 for finish.

## Correlation v4

The canonical correlation schema advances from v3 to v4 and requires both:

- `leader_supervisor_wait_status`; and
- `leader_kernel_wait_status`.

The decoder rejects missing fields, non-minimal or out-of-range values, a supervisor value that
does not match the protected completion, and any kernel/supervisor disagreement. The decoded
correlation object retains both source values for downstream evidence inspection.

Typed leader-exit evidence continues to expose the normalized exit code or signal. The exact raw
statuses remain in the correlation layer, where their source distinction and equality are
explicit. This avoids silently discarding the core bit while also avoiding two redundant typed
terminal representations in the process-event payload.

## Fail-closed tests

The final tests cover:

- exit `0`, nonzero exit `7`, ordinary signal `9`, and signal `11` with a core-dump bit;
- raw/typed exit mismatch;
- raw/typed signal mismatch;
- stopped-state and out-of-range signal encodings;
- finish-v3 raw-status mismatch;
- correlation supervisor/completion mismatch;
- correlation kernel/supervisor mismatch; and
- either required correlation status being absent.

Canonical JSON decoding still denies unknown fields and noncanonical representations.

## Validation

- Final package-sensor Rust library suite: 184 passed.
- Complete `whoathere-macos-vm` package test suite: passed after the implementation change.
- Native package-wide Clippy with all targets and warnings denied: passed.
- Linux/aarch64-musl package-wide Clippy with all targets and warnings denied: passed.
- Static aarch64-musl release build of the package execution runner through `cargo zigbuild`:
  passed.
- Rust formatting and `git diff --check`: passed.

Tracked source identities for this checkpoint are:

| Source | SHA-256 |
| --- | --- |
| Process supervisor and exact completion | `6f47ad703f2985ddde9c500a5fdd2f8fa37d85b8408e32789b448ddcc9929587` |
| Protected sensor control | `e6ec5ec533b9a3eb261cc572636282b4dbde08f0031a586fcc7d2afd60bd4670` |
| Process-sensor correlation | `5fc763edb4447865fad536deab0fc431f148a45c0bb042e91357a75374c6b622` |
| Typed process evidence decoder and fixtures | `adf46d07a12601b81f9c924437a8db870289bbec5a2e2919fcc0092472cb1409` |

## Remaining integration gap

The next slice is the concrete production root collector. It must:

1. own the measured BPF producer and ring-buffer consumer;
2. retain the final cgroup-bound leader exit observation;
3. prove that observation belongs to the blocked leader and expected launch identity;
4. pass the event's raw kernel wait status into correlation v4;
5. reject missing exits, duplicate exits, loss, unfinished syscall pairs, and terminal mismatch; and
6. derive canonical typed process evidence only after those checks pass.

After that, first-class fanotify/file collection, post-run filesystem diff, physical network
qualification, authenticated evidence envelopes, full runtime integration, inert npm/wheel/sdist
scenarios, benign controls, known-malware regression, and held-out gates remain required. Known
malware regression remains restricted to fresh disposable Linux VZ guests on the approved cloud
Mac.
