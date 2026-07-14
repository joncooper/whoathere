# Artifact-Native Linux VZ Package Sensor BPF Producer Checkpoint

Date: 2026-07-14

Status: generated lifecycle producer implemented and cross-compiled; physical kernel acceptance and
service integration remain open

## Outcome

The package sensor now has its first non-fixture BPF producer implementation for lifecycle events.
It does not execute a package and has not been loaded into a physical guest yet.

The implementation:

- reads the pinned guest's `sched_process_fork`, `sched_process_exec`, and `sched_process_exit`
  tracepoint `format` files through fixed tracefs paths;
- strictly validates the tracepoint name, nonzero runtime id, common fields, event-specific fields,
  offsets, sizes, signedness, data-location encoding, overlap, record bounds, and exact format hash;
- creates a root-owned read-only-to-program cgroup configuration map, a fixed-size BPF ring buffer,
  and an atomic reserve-failure counter;
- generates `BPF_PROG_TYPE_TRACEPOINT` programs from the validated field offsets rather than
  assuming a kernel layout;
- filters every event on the exact held cgroup id before reserving ring-buffer space;
- initializes every byte of the closed 192-byte event record before submitting it;
- attaches each lifecycle program through a perf event on every strictly parsed online guest CPU;
- increments the protected drop counter when a ring reservation fails; and
- keeps map, program, and attachment descriptors close-on-exec and owned by the root producer.

The UAPI prefixes and instruction encoding are asserted in native tests against the Linux UAPI
layout. The implementation follows the kernel's documented tracepoint-format contract, perf-event
BPF attachment interface, and ring-buffer reservation semantics:

- [Linux event tracing](https://docs.kernel.org/trace/events.html)
- [Linux BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html)
- [Linux BPF UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h)
- [Linux perf-event UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/perf_event.h)

## Verification

The focused sensor suite passes, including:

- all five required tracepoint-layout families;
- missing, duplicate, overlapping, incompatible, noncanonical, and oversized format rejection;
- exact one-pass format hashing;
- bounded, forward-only generated lifecycle programs;
- full fixed-record initialization;
- exact map-descriptor instruction encoding;
- exact Linux UAPI prefix sizes and offsets; and
- strict bounded online-CPU parsing.

Native Clippy and `aarch64-unknown-linux-musl` all-target Clippy pass with warnings denied.

## Claim Boundary

This checkpoint does **not** establish that the pinned guest kernel accepts the generated programs,
that the perf attachments observe a physical inert process, that the service driver consumes the
stream, or that lifecycle coverage is complete. Syscall programs, fanotify collection, filesystem
diffing, canonical evidence construction, signing, runtime rebuild, and physical inert
qualification remain open.

No package or malware ran. The July malicious-package result remains 7 of 11 behavior detections.

All future real-malware execution is restricted to the approved cloud Mac and a fresh disposable
Linux VZ guest. It must never occur on an operator's local Mac, in this workspace, or in Docker,
and it still requires the separate reviewed lab gate.

## Next Gate

1. Add a measured inert probe that loads these programs in the pinned Linux VZ guest and proves an
   exact cgroup-bound exec/exit lifecycle with zero drops.
2. Add selected syscall enter/exit programs and semantic network extraction without exposing raw
   untrusted pointers or addresses.
3. Integrate the producer and consumer with the protected service collector.
4. Add fanotify and post-exit filesystem diff collection.
5. Build canonical authenticated evidence, rebuild the measured runtime, and rerun the inert
   physical gate on the approved cloud Mac.
