# Artifact-Native Linux VZ Package Root Process Fault-Propagation Checkpoint

Date: 2026-07-14

Status: process-worker fault signaling and descriptor-relative cgroup termination implemented; the
collector-to-kill path physically qualified with a purpose-built inert fixture on the approved
cloud Mac

## Outcome

The continuously draining process collector now has an asynchronous failure path. Arm creates a
nonblocking, close-on-exec kernel pipe before the BPF worker starts. The owner retains the read end;
the worker retains the write end. The first active producer, stream, sequence, loss, accounting, or
worker fault permanently records the fault and writes one marker. A worker panic or unexpected exit
closes the write end, so either readability or hangup is terminal.

That signal is now carried through the protected execution architecture:

- the concrete process component implements the root sensor-service collector boundary;
- the service requires a distinct valid fault descriptor before either arm or leader
  acknowledgement;
- after leader acknowledgement, the service polls the authenticated control socket and collector
  fault descriptor together;
- a collector fault is prioritized over a simultaneous finish request;
- the service writes `1` to `cgroup.kill` through the already validated transferred cgroup
  directory descriptor, aborts collector resources, releases the descriptor, and closes the
  authenticated control channel; and
- the root-runner observer checks that channel before child release and around every 25 ms running
  poll and every 10 ms teardown poll. Unexpected readability, error, or hangup faults the observer;
  the local cgroup owner then also performs fail-closed cleanup.

The concrete adapter is intentionally **process-only**. It reports the file and network collectors
unavailable. The root service therefore refuses arm and cannot release a package when this adapter
is used by itself. Its process collection also cannot be represented as complete finish output:
typed process evidence, protected file/network evidence, and the composite correlation remain
required.

This checkpoint removes the previous “learn about a process sensor fault only at finish” defect. It
does **not** complete package-integrated telemetry or change the malicious-package result. The July
score remains **7/11 (63.6%)**.

## Safety boundary

No package and no malware sample ran. The physical qualification used the existing purpose-built
inert fixture twice inside one fresh disposable Linux VZ guest:

1. the normal 50 ms case proved the complete continuous-drain path remained intact; and
2. a second run deliberately set the collector source-event limit to eight, causing the fixture's
   inert credential/exec/loader activity to exceed the limit and fault the collector.

The second case did not perform external I/O or add a selected package-risk behavior. The probe
required the protected fault marker, invoked the same descriptor-relative cgroup-kill helper used
by the service, required the second fixture to terminate by `SIGKILL`, aborted BPF resources, and
removed the empty cgroup.

The guest had no external route, root disk, directory share, or sync-back path. The strict host
verifier observed zero raw frames, stable images, and a stopped VM. Real malware remains
cloud-Mac-only and may execute only inside a fresh disposable Linux VZ guest under the separate
restricted-lab workflow. It must never execute in the local workspace, in Docker, or directly on
either Mac host.

## Fail-closed contracts

### Collector fault descriptor

The fault pipe is created with `O_NONBLOCK | O_CLOEXEC`. Both ends are validated as distinct owned
descriptors. The read end is available only while the collector is armed or leader-attached. A
zero-time health poll succeeds only when no fault event is present. The marker remains unread, so
the signal is level-triggered for every subsequent poll. Closing the worker side also remains
observable as hangup.

The worker records only the first fault. Marker writes retry `EINTR`; a full pipe is already a
readable terminal signal. Faulted workers continue best-effort ring draining until finish or abort,
but can never return complete evidence.

### Protected root service

The service accepts the fault descriptor only after the cgroup directory has been received by
descriptor passing and independently checked as root-owned cgroup v2 state. While the package is
running, it polls only:

- the authenticated root-only control socket; and
- the active composite collector fault descriptor.

On fault, the service does not trust a path supplied by the package or root runner. It opens
`cgroup.kill` relative to the already validated directory descriptor with `O_NOFOLLOW`, writes the
kill request, aborts sensors, drops the active binding, and shuts down both directions of the
control socket.

### Root-runner supervisor

No unsolicited service message is valid while a package is running. The observer therefore treats
control-socket readability, error, or hangup as a protected sensor fault. Health is checked once
after the held leader is correlated but before release, then before and after every bounded output
poll during execution and teardown, and once more before finish. A fault returns
`ProtectedSensorUnavailable`; the root runner's owned cgroup cleanup remains an independent second
kill path.

## Physical qualification

The strict schema-v7 host verifier exited `0` with canonical `status: "ok"`.

The retained normal case proved:

- 39 active drain polls and two nonempty polls;
- all 14 source records consumed before finish, with zero finish-drain records;
- maximum drain batch size `13`;
- source sequence `1..14`, eight exact correlated observations, and one leader exec/exit;
- CPU 1 delivery from the CPU 0 tracepoint-wide attachment;
- exact kernel and independent supervisor wait status `0`; and
- zero pre-release events, producer drops, or consumer discards.

The new injected-fault case proved:

- source-event limit `8` and trigger `source_event_limit`;
- a readable nonblocking pipe marker rather than worker hangup;
- fault-marker latency **1,271 microseconds** from leader release;
- a distinct second fixture PID and cgroup;
- descriptor-relative `cgroup.kill` use;
- exact second-fixture termination signal `9` (`SIGKILL`); and
- collector abort plus successful empty-cgroup removal.

Across the complete run, package execution, malware execution, and sync-back were false; host raw
frame count was zero; no storage device or directory share was attached; and the VM stopped before
acceptance.

The canonical schema-v7 evidence was 2,244 bytes with SHA-256
`bfc85dc6738c49a8fdaf39115d3c62e81faf061a993d292d7dc35b5021ca3bee`. The sanitized serial
transcript was 3,092 bytes with SHA-256
`dd293fdfafec92316ff515b6cf6a043ba12b079f7635bfbce115958d568b566c`.

Exact final inputs were:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 10,148,959 | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Guest init | 1,750 | `6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Static fault-propagation inert probe | 782,624 | `79bdef133c041cf282855fad8afd428b95d230e30c9f8f834b035b2b109618c3` |
| Static inert fixture | 371,736 | `09933b6efc035a0d6c43ca3cf63e76e5d49ada432c7418e7e929b60c9d613b7e` |
| Canonical overlay CPIO | 1,157,120 | `2506a54cd64d28c99d19bd4b1064ec76b88e7744fc980c8572d1daabcc0c4f00` |
| Deterministic gzip overlay | 595,914 | `cb19b93338ad604d1474fa68b881bd72737c5c773dba4642870fb42eb15359c2` |
| Combined qualification initramfs | 10,744,873 | `1593e92845b774f36d286180479757f93e843cfc6ce26aab606e8f4db9ae20a7` |
| Strict entitled Mac verifier | 2,840,640 | `f30c9c01e61d7b0670fe7216328ba2dca94687fd51e330791a8adf8d9f3a0bbe` |

Two independently generated overlay CPIO and deterministic gzip outputs were byte-identical. The
verifier signature was valid and carried only the macOS virtualization entitlement. Kernel,
initramfs, and verifier hashes remained unchanged after the run.

Runtime BTF SHA-256 remained
`d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb`, and the
`task_struct.exit_code` byte offset remained `1964`. Runtime tracepoint-format identities were also
unchanged:

| Tracepoint | SHA-256 |
| --- | --- |
| `sched_process_exec` | `f8af16db8c47534beaff9b2f477b6d309df3512f9386e0bdc079b7a5618043ba` |
| `sched_process_exit` | `b04a7c7b2e0c473705fe812851c161126b0a68f3eab604e92da952a241eb5870` |
| `sched_process_fork` | `84863bfaed832693cea3a4be6992a28a4d578c9bfc5cbef787a251c81a12e52f` |
| `sys_enter` | `a0a15f3bed75f08c1804f593b6164c023a85e722b8e59a0ba0b21dd66add4d5e` |
| `sys_exit` | `f8e577e78684157c4e0f22853b7b90b06119e8ff454d5873805a0857ec86fd75` |

## Validation

- Package-sensor Rust library suite: 188 passed on macOS.
- Swift helper suite: 200 passed.
- Native package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64-musl package-wide `cargo clippy --all-targets -- -D warnings`: passed, including
  compilation of the Linux-only pipe and observer channel-teardown tests.
- Static aarch64-musl release probe and fixture build through `cargo zigbuild`: passed.
- Release Mac verifier build, ad-hoc virtualization-entitlement signing, and strict signature
  verification: passed.
- Two deterministic overlay builds: byte-identical.
- Exact normal plus injected-fault physical inert qualification: passed.
- Formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Process supervisor | `e059c9429cc61e3082576bbf136f1f7830b0707fd754c5f0d182d9c330736070` |
| Root sensor control and process adapter | `c4269c4a8b9a18dbd815a5879c4d37ca00e5f23cd3d34e67834bf7f7e6406050` |
| Root process collector | `074d432ed334dcd72c048b5597bdcd02e3f98169a19140a1e9229934b40d7a8c` |
| Normal and fault inert probe | `c2a8506561b4cf75039c418173f6427e909239f0cee81e09ba2e1e958ae60a36` |
| Strict Swift evidence decoder | `792d23d25f08afc1006b3e6eae95c06b73db6e8996b60cc9be37874397f708d2` |
| Strict Mac verifier | `46e77550bf5e0b36b9d944f6411d35adc29d2342741b65264b29a112f71bb73a` |
| Swift decoder tests | `1c180140a23f0ab032383aabf01b1af1bfcba22eec9df4b8d120956efe321920` |

## Claim boundary and next step

The physical test proves the concrete collector's first-fault marker and the exact
descriptor-relative cgroup-kill helper. Linux-target compilation includes closed tests for service
polling and root-runner channel-teardown handling; those tests were compiled, not executed, in this
macOS-hosted run. A full two-process root-service/root-runner
physical package session is not yet qualified, because the service correctly refuses release
without file and network collectors.

Next, encode the completed correlated process stream as canonical typed process evidence bound to
the session challenge, measured launch identity, action, cgroup, terminal status, and exact
collector health. Then implement the protected fanotify/filesystem-diff and network collectors,
compose all three fault descriptors and payloads into one authenticated evidence envelope, and
physically qualify that full service with inert npm, wheel, and nested-sdist scenarios. Benign
scoring and the restricted cloud-Mac malicious regression remain later gates.
