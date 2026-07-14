# Artifact-Native Linux VZ Package-Sensor Process Correlator Checkpoint

Date: 2026-07-14

Status: fail-closed per-thread syscall correlation physically qualified with an inert fixture on
the approved cloud Mac

## Outcome

The package-sensor process stream now converts the raw BPF event stream into a closed correlated
stream before any record can become package-behavior evidence. It pairs each selected syscall
entry and exit by exact `(tgid, tid)`, preserves the entry and exit sequence/timestamp/CPU values,
requires the same syscall and cgroup on both sides, and retains only the arguments already
redacted by the BPF producer. Interleaved syscalls from different threads are supported without
pair substitution.

The correlator faults permanently on its first invalid event. It rejects a sequence gap,
non-increasing timestamp, wrong cgroup, duplicate entry, exit without entry, syscall mismatch,
process exit with a pending syscall, unfinished syscall at finalization, count disagreement, any
BPF reservation drop, any discarded ring record, nonempty or truncated producer detail that the
correlator cannot consume, or more than 65,536 source events. Debug output does not expose the
retained argument values.

The final static probe, with this correlator in its live path, passed the strict physical inert
gate on the approved cloud Mac. The exact 14 source events became eight ordered correlated
observations:

1. successful `setgroups`, `setgid`, and `setuid` pairs;
2. one `exec` lifecycle observation;
3. three successful runtime-linker `mmap` pairs; and
4. one `exit` lifecycle observation.

The run recorded zero BPF reservation drops, zero discarded ring records, zero raw Ethernet
frames, no disk or directory share, stable measured image bytes, and a stopped VM. Package
execution, malware execution, and sync-back were all false. This proves the correlation primitive
and its live integration with the inert producer; it is not yet protected-service integration or
verdict-grade typed process evidence. The July malicious-package score remains **7/11 (63.6%)**.

## Safety boundary

No package or malware code ran. The only guest payload was the purpose-built static inert fixture.
The fresh disposable Linux VZ guest had no root disk, no directory share, and only a host
raw-frame sinkhole with no external route. No sync-back path existed.

Real malware remains a separate restricted-lab operation. It may run only on the approved cloud
Mac, inside a fresh disposable Linux VZ guest, after the separate approval gate. It must never run
in this workspace or in Docker, must never use sync-back, and must not contact live C2 or retrieve
a live second stage.

## Correlation contract

### Exact per-thread pairing

The pending-syscall key is the exact kernel `(tgid, tid)` pair. A thread may have at most one
selected syscall pending. Entry and exit must agree on:

- selected syscall identity;
- cgroup ID;
- TID and TGID;
- strictly increasing source sequence; and
- strictly increasing monotonic timestamp.

Different threads may interleave. Final correlated observations are ordered by their first source
sequence, so an interleaved syscall retains its original entry position even if another thread
finishes first. Entry and exit CPU values are both retained because a thread may migrate during a
syscall; CPU equality is not incorrectly required.

The paired result retains the signed kernel return value. The BPF-enforced argument shapes remain
closed:

- credential syscalls retain only their scalar count or UID/GID argument;
- `connect` retains socket FD and address length;
- `sendto` retains socket FD, byte count, flags, and address length; and
- `mmap` retains length, protection, flags, FD, and offset.

Pointers remain zero. The raw event decoder independently rejects a nonzero redacted field before
the correlator can see the event.

### Fault and coverage semantics

Any invalid input latches the correlator into a faulted state. A corrected retry cannot resume the
stream, and a faulted stream cannot finalize. Successful finalization requires:

- at least one source event;
- exact contiguous source sequence from `1` through the producer's final sequence;
- no pending syscall;
- no BPF reservation drops;
- no discarded ring record; and
- a bounded, strictly ordered correlated observation set.

This is intentionally stricter than merely finding a suspicious call. Incomplete telemetry cannot
be represented as complete clean evidence.

## Physical qualification

The final successful run used these exact inputs:

| Component | SHA-256 |
| --- | --- |
| Pinned Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | `sha256:9e6519ef2034469a1fbb298f4a1fb7653576eb7287600b1d9b0c75c6a2d0ae45` |
| Guest init | `sha256:6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Final correlator-enabled static probe | `sha256:3dd99892ea457acb330c261d63614b7568310f01317b4336a14932ed001b4cb9` |
| Inert fixture | `sha256:c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6` |
| Canonical overlay CPIO | `sha256:63f51077b72a3306fdbbc04a464d2220c9946ead02c3af4165c66af5a396fd67` |
| Deterministic gzip overlay | `sha256:e85327d50ff956d91dbcf1f3dd4e256a1c6b6f68e293c850e0d0df6f246edc97` |
| Combined qualification initramfs | `sha256:fff0d5c57efe7fd746c3be45d433fc3f5c660bc01bb64d73b9d1bfa927f2af8d` |
| Strict ad-hoc-signed host harness | `sha256:b0d1b42e8346a7ff6d64757278e16308efc89f1b3c560a872f54a136d1fc8892` |
| Sanitized serial transcript | `sha256:23ddd52d9209816f50802af0b529c8bd5de6d1cdb6ab6c88bd79b74fa562bc09` |

The overlay CPIO was `1,015,296` bytes, its deterministic gzip form was `530,972` bytes, the
combined initramfs was `13,003,194` bytes, and the static probe was `641,384` bytes. The sanitized
serial transcript was `2,081` bytes.

The canonical guest evidence payload was `1,233` bytes with SHA-256
`sha256:960c78482f54a3dced9011139095c3c4e7ba12f1f2a8d75a4fda34ab67cce87a`.
It bound cgroup ID `21`, fixture PID `387`, source sequence `1..14`, online CPUs `0` and `1`, the
five exact tracepoint format hashes from the selected-syscall checkpoint, and zero loss. The host
harness exited `0` with canonical `status: "ok"` and independently required the same image,
topology, safety, and VM-stop invariants.

Key tracked source identities were:

| Source | SHA-256 |
| --- | --- |
| Process correlator | `sha256:f30e34b37f912f8b3462098ae187b600d037290c098789612cd9e42fb9dadfc7` |
| Correlator-enabled inert probe | `sha256:65f652d064a3a4cd75a2f983639d9af577e4a58afa845acbaf429b728f927980` |
| Crate module boundary | `sha256:57c9a9bf48b5e788cf823787deab71a9bd17cdfe46cc198d549973a97f49d462` |
| Cargo lock | `sha256:0635890ecb3d8b03c683983b3799e2a8fd6aa6252eb914b6e0cc227804f85b93` |

## Validation

- Package-sensor Rust library suite: 175 passed.
- Native package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64 package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Static aarch64-musl release build through `cargo zigbuild`: passed.
- Strict physical inert qualification on the approved cloud Mac: exit `0`, canonical
  `status: "ok"`.
- Formatting and `git diff --check`: passed.

## Remaining integration gaps

This checkpoint exposes three concrete requirements for the production root-service adapter:

1. The initial package leader is forked while stopped and is moved into the package cgroup only
   afterward. A cgroup-filtered BPF producer therefore cannot observe that initial fork. The
   supervisor/service protocol must bind a trusted leader-start observation without pretending it
   came from BPF.
2. The current lifecycle producer does not retain `sched_process_exit.exit_code`. Verdict-grade
   process evidence needs that exact terminal value or an independently bound supervisor terminal
   result.
3. The current exec event intentionally captures no raw argv or path. The protected service needs
   an exact launch-contract-bound executable digest, argv digest, and argv item count without
   accepting unbound caller claims or raw package-controlled strings.

The correlator also does not yet convert successful `setgroups`/`setgid`/`setuid` into one typed
credential-change observation, convert `mmap` into file evidence, or correlate `connect`/`sendto`
with the qualified host raw-frame stream. `connect` and `sendto` remain physically unqualified in
this production-candidate producer.

The next work is to close that supervisor-to-service execution binding, capture/bind exact terminal
status, instantiate the BPF producer and correlator inside the protected root collector, and then
physically qualify `connect` and `sendto` against the inert sinkhole. Fanotify/file collection,
post-run filesystem diffing, signed `EvidenceEnvelope` production, benign controls, known-malware
regression, and held-out gates remain open.
