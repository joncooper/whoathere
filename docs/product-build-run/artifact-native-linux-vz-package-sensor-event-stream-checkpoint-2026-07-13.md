# Artifact-Native Linux VZ Package Sensor Event-Stream Checkpoint

Date: 2026-07-13

Status: a closed arbitrary-event ABI and bounded Linux BPF ring-buffer consumer are implemented and
cross-compiled; no BPF producer is loaded or attached yet, so this does not observe package behavior

## Outcome

The measured conformance sensor stores one observation per fixture-selected behavior in a fixed
`BPF_MAP_TYPE_ARRAY`. That is useful for proving individual inert capabilities, but it cannot
represent an arbitrary package's ordered stream of forks, execs, exits, syscalls, or repeated
network activity. Treating it as the production package collector would silently collapse repeated
events and overstate detection coverage.

This checkpoint adds the receiving foundation for a real stream:

- one exact 192-byte kernel-event ABI for fork, exec, exit, selected syscall-enter, and selected
  syscall-exit observations;
- strict cross-cgroup, process, field-use, reserved-byte, truncation, and length validation;
- a root-only userspace consumer for `BPF_MAP_TYPE_RINGBUF`; and
- explicit handling for busy records, discarded records, mapping limits, malformed records, and
  bounded draining.

The module remains crate-private. No BPF program currently produces these records, the service
driver does not yet instantiate the consumer, and no event from a package has been observed.

## Closed kernel-event ABI

Every event is exactly 192 little-endian bytes and contains:

- fixed magic, version, kind, flags, and record length;
- the exact kernel cgroup ID and monotonic timestamp;
- PID, TGID, and typed parent/subject PIDs;
- a selected syscall number, address family, optional result, and six numeric arguments;
- at most 64 bytes of bounded raw detail with an explicit truncation bit;
- the producing CPU; and
- zeroed reserved regions.

The decoder requires the exact expected cgroup ID supplied by the held cgroup descriptor. Process
events cannot smuggle syscall arguments, result values, address families, or unused bytes. Fork
requires a distinct child and the exact actor/parent PID relationship. Exec and exit require the
subject PID to equal the actor PID. Syscall enter cannot claim a result; syscall exit must. Unknown
kinds, flags, address families, nonzero reserved bytes, invalid process IDs, inconsistent field use,
and nonzero unused data tails fail closed.

Raw arguments and raw detail are never printed by `Debug`. They remain available only inside the
crate for the future sanitizer, which must convert addresses, names, paths, and arguments into the
existing typed/hashing evidence vocabulary before serialization. The kernel record reserves its
sequence field as zero. The userspace consumer assigns the only stream sequence in ring-reservation
order, avoiding a false cross-CPU ordering claim from an independent BPF atomic counter.

## Ring-buffer consumer

The Linux consumer takes ownership of an already-created map descriptor and requires:

- root effective UID/GID and close-on-exec on the descriptor;
- `BPF_OBJ_GET_INFO_BY_FD` proof that the object is exactly `BPF_MAP_TYPE_RINGBUF` with zero key and
  value sizes and the configured capacity;
- a capacity from 64 KiB through 16 MiB that is both a power of two and page-aligned; and
- the standard writable consumer-page mapping plus read-only producer page and double-mapped data
  region.

Producer and consumer positions are read and published with acquire/release atomics. The consumer
honors the kernel busy and discard bits, applies eight-byte record alignment, permits wraparound
only through the kernel's double mapping, refuses a producer/consumer distance larger than the
configured capacity, and rejects any payload that is not exactly one event record. Each accepted
record receives a checked monotonically increasing userspace sequence. Discarded-record count is
retained separately and must make later evidence incomplete.

This does not replace the required BPF-side reservation-failure counter. The future producer must
increment a protected counter whenever `bpf_ringbuf_reserve` returns null; finish must require both
that counter and userspace discarded-record count to be zero.

The layout and ordering implementation follows the Linux kernel's
[BPF ring-buffer documentation](https://docs.kernel.org/bpf/ringbuf.html), including the single
multi-producer buffer, reservation ordering, busy/discard record header, eight-byte alignment, and
consumer/producer mappings.

## Verification

Verification was non-malicious and did not launch a VM:

- all 159 `whoathere-macos-vm` native library tests passed;
- three new native unit tests cover all five event kinds, raw-debug redaction, header/version/kind/
  length/cgroup/reserved-byte mutation, invalid process IDs, invalid flags, invalid data lengths,
  nonzero unused tails, and invalid assigned sequence;
- Linux/aarch64-musl all-target Clippy passes with warnings denied, type-checking the BPF map-info,
  mmap, atomic, wraparound, record-header, and unmap paths; and
- formatting passes.

The ring-buffer mmap path has not executed in Linux yet. A cross-compile is not evidence that the
kernel accepts a future producer, that tracepoints attach, that loss accounting is complete, or
that behavior detection improved.

## Remaining boundary

The next collector work is:

1. strictly parse the pinned guest kernel's tracepoint field layouts;
2. create the ring buffer plus expected-cgroup and reservation-drop maps;
3. load and attach cgroup-filtered tracepoint programs for fork/exec/exit and selected syscall
   enter/exit events;
4. execute an inert multi-event producer/consumer test inside a fresh Linux VZ guest on the
   approved cloud Mac;
5. add fanotify permission/notification collection and the mandatory post-run filesystem diff;
6. sanitize and map the raw stream into the existing canonical process/file/network schemas; and
7. wire the real collector into the internal service driver before exposing any production entry
   point.

The malicious-package detection score remains 7 of 11. Real malware may run only on the approved
cloud Mac, only inside a fresh disposable Linux VZ guest under the restricted lab workflow, and
never with sync-back, live C2, or live second-stage fetching.
