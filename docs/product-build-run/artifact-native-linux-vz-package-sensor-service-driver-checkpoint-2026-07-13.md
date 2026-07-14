# Artifact-Native Linux VZ Package Sensor-Service Driver Checkpoint

Date: 2026-07-13

Status: the receiving root-only control protocol, kernel-backed cgroup/leader validation, and
automatic failure teardown are implemented and cross-compiled; the driver remains crate-internal
because the arbitrary-package event collector and signed evidence producer do not exist yet

## Outcome

The prior checkpoint implemented the supervisor-side protected observer and the root-only control
client. This checkpoint implements the other half of that protocol as a strict single-session
service driver.

The driver can receive and retain the exact cgroup-v2 directory descriptor, validate the cgroup and
blocked leader from kernel state, call a separate collector boundary, return only the closed
acknowledgments and evidence sequence accepted by the observer, and tear down collector state on
every incomplete exit. It does not implement the collector. It therefore cannot observe arbitrary
package behavior, cannot produce legitimate package evidence, and is deliberately not exported as
a production service entry point.

No package manager, package artifact, VM, cloud host, or malware sample was executed while
implementing or testing this checkpoint.

## Root peer and session binding

The service applies the same root-only Unix-stream checks as the client:

- the service process must have root real, effective, and saved UID/GID;
- the stream must be a root-owned, root-group Unix `SOCK_STREAM` with close-on-exec;
- `SO_PEERCRED` must identify a distinct root process with PID greater than one;
- read and write deadlines are ten seconds; and
- the first frame must be the exact canonical open-session request at sequence one.

The open request must bind the service's independently supplied measured qualified-backend, guest
evidence-signer, protected-sensor-bundle, and sensor-configuration digests; a fresh nonempty session
challenge; package UID/GID `65534`; root runner UID/GID; no public route; and no sync-back. The
collector must pass its readiness check before the service acknowledges readiness. A readiness
failure invokes collector abort even though no action has been armed.

The SHA-256 in each frame is corruption and mutation detection, not peer authentication. The
channel still relies on the measured root processes and their Unix peer credentials. Guest and host
signatures remain a later required gate.

## Descriptor receipt and cgroup proof

The service receives each request header with `recvmsg(..., MSG_CMSG_CLOEXEC)` so the `SCM_RIGHTS`
descriptor attached to the first byte of an arm frame cannot be lost through ordinary stream
reads. It rejects truncated ancillary data, truncated frames, unknown control messages, more than
one descriptor, descriptors on non-arm frames, or an arm without exactly one descriptor. Received
descriptors must have close-on-exec set.

Before arming a collector, the service independently requires that the transferred descriptor:

- identifies a root-owned and root-group directory on cgroup v2;
- has a nonzero kernel inode used as the cgroup ID;
- resolves through `/proc/self/fd` to the exact generated action cgroup name; and
- has an empty `cgroup.procs` file.

The service retains ownership of that descriptor before invoking the collector. If arming fails,
returns inconsistent health, or the acknowledgment cannot be written, automatic teardown receives
the exact action context and still-open cgroup descriptor.

## Leader release gate

After the supervisor places its forked child into the cgroup, the service requires `cgroup.procs`
to contain exactly the requested leader PID. It separately reads `/proc/<pid>/cgroup` and requires
the one unified-hierarchy membership to end in the exact held cgroup name. It also requires all
four real/effective/saved/filesystem UID and GID values in `/proc/<pid>/status` to remain root.

This root credential check is intentional: the measured supervisor blocks the child on a private
release pipe before dropping permanently to UID/GID `65534`. The service response ordering proves
that the measured supervisor has not issued that release yet; the service does not claim to inspect
the private pipe itself. Only after exact membership, collector-active health, a heartbeat, and zero
BPF drops does it acknowledge the leader. A failed acknowledgment prevents the supervisor from
releasing the child.

## Finish and automatic abort

Finish is accepted only after the exact leader has been correlated and `cgroup.procs` is empty.
The service requires it to remain empty across collector finalization. A collector result is
eligible to cross the channel only when it contains nonempty bounded correlation, process, file,
and network payloads, at least two heartbeats, zero dropped events, three healthy sensors, complete
descendant teardown, and complete sensor teardown. The driver then releases its cgroup descriptor,
sends the four evidence frames in the fixed order, and sends a final acknowledgment binding every
length and digest.

Abort is accepted only in the session-open, armed, or leader-correlated state and must bind the
exact prior state and optional action context. It emits no evidence. EOF, timeout, malformed input,
wrong ordering, a collector error, an inconsistent health report, or a partial response takes the
same fail-closed path through `Drop`: invoke collector abort, release the held cgroup descriptor,
and close the channel. Collector abort is required to be idempotent because an explicit abort error
is retried during automatic teardown.

## Verification

Verification remains non-malicious and source-level:

- all 156 `whoathere-macos-vm` native library tests passed;
- native all-target Clippy passed with warnings denied;
- Linux/aarch64-musl all-target Clippy passed with warnings denied;
- the Linux-only ancillary test constructs an inert Unix socket pair, transfers `/dev/null`, and
  verifies exact frame preservation plus close-on-exec on the received descriptor; it was
  cross-compiled for the guest target but has not yet been executed in a Linux VZ guest; and
- formatting and `git diff --check` passed.

Cross-compilation proves that the musl/Linux control-message ABI type-checks. It does not prove
runtime cgroup behavior, collector coverage, evidence authenticity, or improved detection.

## Remaining boundary

The next required work is to implement the actual arbitrary-package collector rather than expose a
fixture-backed service:

1. add a cgroup-filtered BPF ring-buffer event stream with explicit reservation/drop accounting;
2. add protected fanotify permission/notification coverage and the mandatory post-run filesystem
   diff;
3. map raw kernel observations into the existing sanitized canonical process/file/network schemas;
4. bind those payloads and the sequencer transcript into guest and host signatures and an
   authenticated `EvidenceEnvelope`;
5. rebuild and independently qualify the exact runtime; and
6. execute inert npm CI=false/true, wheel, and nested-sdist scenarios in fresh disposable Linux VZ
   guests on the approved cloud Mac before any restricted regression.

The malicious-package detection score remains 7 of 11. Real malware may run only on the approved
cloud Mac, only inside a fresh disposable Linux VZ guest under the restricted lab workflow, and
never with sync-back, live C2, or live second-stage fetching.
