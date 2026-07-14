# Artifact-Native Linux VZ Package Root Process Continuous-Drain Checkpoint

Date: 2026-07-14

Status: root-owned continuous process-event draining physically qualified with a purpose-built
inert fixture on the approved cloud Mac

## Outcome

The concrete package process collector no longer leaves its BPF ring unread until finalization.
Arm now starts a dedicated root-owned worker that creates and retains the BPF producer, mapped ring
consumer, and fail-closed correlator on the same thread. The worker polls every millisecond while
the package leader runs, drains every available bounded batch, and keeps exact accounting for the
records consumed before the protected finish command and during finalization.

The final inert physical qualification proved that this was real active draining rather than a
renamed finish-only path:

- the worker completed 38 active drain polls;
- one active poll was nonempty;
- that poll consumed and correlated source records `1..13` while the leader was still running;
- finalization consumed only source record `14`, the leader exit;
- the maximum individual drain batch contained 13 records; and
- all 14 source records still became the exact eight expected correlated observations.

The existing strict properties remained true: pre-release event count zero, producer drop count
zero, consumer discard count zero, exact CPU 1 delivery from a CPU 0 tracepoint attachment,
complete syscall pairing, one leader exec, one BTF-derived leader exit, and byte-exact agreement
between kernel and supervisor raw wait statuses.

This removes the known finish-only ring-pressure defect. It does **not** complete the protected
root service or package-detection pipeline. The collector is still crate-private and not yet
adapted into `LinuxVzPackageRootSensorServiceCollectorV1`. A worker fault makes final evidence fail
closed and the worker retains/drains its protected producer until finish or abort, but the current
service protocol does not yet propagate an asynchronous sensor-fault signal that can terminate a
running package immediately. File/fanotify, filesystem-diff, network, composite-envelope, runtime,
benign, and malicious gates remain open. The July malicious-package score remains **7/11 (63.6%)**.

## Safety boundary

No package and no malware sample ran. The only executed guest payload was a purpose-built inert
fixture. Its new closed `continuous_drain` case performs the existing UID/GID, supplementary-group,
no-new-privileges, and core-limit checks, sleeps for exactly 50 ms, and exits `0`. The sleep creates
a bounded observation window without adding a selected package-risk syscall or any external I/O.

The final run used a fresh disposable Linux VZ guest on the approved cloud Mac with:

- no external route;
- no root disk or directory share;
- zero host-observed raw frames;
- package execution reported false;
- malware execution reported false;
- sync-back reported false; and
- a stopped VM before the host verifier accepted the result.

Real malware remains cloud-Mac-only and may execute only inside a fresh disposable Linux VZ guest
under the separate restricted-lab workflow. It must never execute in the local workspace, in
Docker, or directly on either Mac host.

## Worker contract

The BPF producer and its raw mapped ring are constructed inside the worker rather than constructed
elsewhere and unsafely moved across threads. Arm does not succeed until that worker has created the
producer and correlator and returned the measured online CPUs and attachment CPU.

The owner and worker exchange only three bounded lifecycle commands:

- `LeaderAttached`, with the exact blocked leader PID and a one-result response;
- `Finish`, with that same PID, the exact supervisor completion, and a one-result response; and
- idempotent `Abort`.

Before leader acknowledgement, the worker continuously checks that the cgroup-filtered stream is
quiet. The acknowledgement path checks again synchronously, so any event, source sequence, drop,
or discard before release faults and tears down the collector.

After acknowledgement, every one-millisecond timeout is an active drain poll. Each poll drains in
bounded batches of at most 4,096 records until the ring is empty, ingests every record into the
per-thread correlator, and checks the protected drop and discard counts. Sequence, timestamp,
cgroup, selected-syscall, pairing, record, producer, or accounting failure permanently faults the
result. After a fault the worker continues best-effort draining to avoid unnecessary ring pressure,
but it can never return complete evidence.

Finish remains valid only after the protected caller has independently proved the cgroup empty and
reaped the leader. The worker performs one final drain, then requires:

- exact source-count equality across worker, producer, and correlator;
- zero producer drops and consumer discards;
- no pending syscall pair;
- at least one exact leader exec and exactly one leader exit;
- exec and exit timestamps inside the supervisor interval; and
- byte-exact kernel/supervisor raw wait-status agreement, including the signal core-dump bit.

Dropping or aborting the owner sends `Abort`, joins the worker, and drops all BPF links, programs,
maps, and mappings. A disconnected command channel also tears the worker down.

## Strict host evidence

Canonical guest evidence schema v6 adds and binds:

- `collector_drain_mode = continuous_worker`;
- `active_drain_poll_count`, from `1` through the strict qualification cap;
- a positive `active_nonempty_drain_count` no greater than total active polls;
- `source_event_count_before_finish` of `13` or `14`;
- `finish_drain_event_count` of `0` or `1`, with an exact sum of `14`; and
- a positive `maximum_drain_batch_record_count` no greater than `14`.

The final record was the stronger `13 + 1` case. The strict Mac decoder retains every schema-v5
collector, topology, loss, BTF, tracepoint, terminal, canonical-JSON, and false-authority check. It
rejects the preceding schema, finish-only mode, no nonempty active drain, insufficient pre-finish
coverage, inconsistent final accounting, excessive batches, unknown or duplicate fields, and
unsafe execution flags.

## Physical qualification

The final strict host verifier exited `0` with canonical `status: "ok"`. It bound:

- collector mode `root_bpf_ring_correlator` and drain mode `continuous_worker`;
- 38 active drain polls and one nonempty active drain;
- 13 source records before finish and one during finish;
- maximum drain batch size `13`;
- tracepoint perf attachment CPU `0`;
- inert fixture CPU `1` and observed event CPUs `[1]`;
- source sequence `1..14`, 14 source events, and eight correlated observations;
- cgroup ID `21` and fixture PID `387`;
- runtime BTF SHA-256
  `d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb`;
- `task_struct.exit_code` byte offset `1964`;
- kernel and independent `waitpid` raw wait status `0`;
- zero pre-release events, producer drops, and consumer discards;
- zero host raw frames; and
- a fully stopped disposable VM.

The canonical guest evidence was 1,937 bytes with SHA-256
`cd239e2b152c44f97452fca47d3908f4439c25f64836877b22681847777e9039`. The sanitized serial
transcript was 2,785 bytes with SHA-256
`ca70b18ca755de0bef38349fed0abc3406591e296b25eae8971794a552d3cf5a`.

Exact final inputs were:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 10,148,959 | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Guest init | 1,750 | `6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Static continuous-drain inert probe | 780,880 | `e8c00018b6f0b0616ce465e30f3ae7a95e38e55178bba2806a1b8cf124389039` |
| Static continuous-drain inert fixture | 371,736 | `09933b6efc035a0d6c43ca3cf63e76e5d49ada432c7418e7e929b60c9d613b7e` |
| Canonical overlay CPIO | 1,155,072 | `398165ad2812b8ee3ecd9ec941c5a02333a3850310e05c7a79cc0b0f0c74410d` |
| Deterministic gzip overlay | 593,597 | `8bdcd53093e45de4c83b4e9c7d10fa162f37c96bef6789018fd2b118778a0121` |
| Combined qualification initramfs | 10,742,556 | `f90c593a5c150c6776b350e6c4eb0f79670c702672724078145d255e20cddb23` |
| Strict entitled Mac verifier | 2,823,152 | `2c29ddbcf936b922c830960c6493a1e63aeffaf46586809193064ce6b7a560e1` |

Two independently generated overlay CPIO and deterministic gzip outputs were byte-identical. The
verifier's signature was valid and carried only the macOS virtualization entitlement.

Runtime tracepoint-format SHA-256 identities were unchanged:

| Tracepoint | SHA-256 |
| --- | --- |
| `sched_process_exec` | `f8af16db8c47534beaff9b2f477b6d309df3512f9386e0bdc079b7a5618043ba` |
| `sched_process_exit` | `b04a7c7b2e0c473705fe812851c161126b0a68f3eab604e92da952a241eb5870` |
| `sched_process_fork` | `84863bfaed832693cea3a4be6992a28a4d578c9bfc5cbef787a251c81a12e52f` |
| `sys_enter` | `a0a15f3bed75f08c1804f593b6164c023a85e722b8e59a0ba0b21dd66add4d5e` |
| `sys_exit` | `f8e577e78684157c4e0f22853b7b90b06119e8ff454d5873805a0857ec86fd75` |

## Validation

- Package-sensor Rust library suite: 188 passed.
- Swift helper suite: 200 passed.
- Native package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64-musl package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Static aarch64-musl release probe and fixture build through `cargo zigbuild`: passed.
- Release Mac verifier build, ad-hoc virtualization-entitlement signing, and strict signature
  verification: passed.
- Two deterministic overlay builds: byte-identical.
- Exact continuous-drain physical inert qualification: passed.
- Formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Root process collector | `400c5bdd017b0bc42366a193dba92cd79d2cb46e4a95ed1aeeece1b802999fde` |
| Continuous-drain inert probe | `abe9b6808624c2ee1c2be8bd011adf7faf2c2fdf1162e05eb17e9df7b7a01132` |
| Continuous-drain inert fixture | `f97b29b31eb99df458e2d2b9c442ebb6f4a4709665617031fb394127d84db0a4` |
| Strict Swift evidence decoder | `a4a19622ec503f4f1a10cc818662c9e94bbe49825a2be41bd0fa67f2eca0e3cb` |
| Strict Mac verifier | `20a4e5518b6624decbb9a59e78d75d4d7ffd3a80398492b39b6e79e94f418a30` |
| Swift decoder tests | `25bfa036bdd8fc381883b30ca9b82037da48f704686f44ef76e588693f359c46` |

## Next step

Adapt the continuously draining process collector into
`LinuxVzPackageRootSensorServiceCollectorV1`. Add an asynchronous protected health/fault path so a
worker failure terminates the held or running package instead of waiting for finish. Convert the
completed correlated stream into canonical typed process evidence and correlation bound to the
service's exact session, action, launch contract, cgroup, and supervisor completion.

The root service must continue refusing execution until protected file/fanotify and network
collectors, their health/loss accounting, and an authenticated composite evidence envelope are all
present. Only then can inert npm, wheel, and nested-sdist scenarios begin; benign scoring and the
restricted cloud-Mac malicious regression remain later gates.
