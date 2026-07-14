# Artifact-Native Linux VZ Package Root Process-Collector Checkpoint

Date: 2026-07-14

Status: concrete process-only root collector physically qualified with a purpose-built inert fixture
on the approved cloud Mac

## Outcome

The package-sensor process path now has a concrete root collector rather than a probe that directly
composes the BPF producer and correlator. The collector owns the root-only BPF producer, ring-buffer
consumer, and fail-closed process correlator from arm through finish. It requires a quiet stream
before the held package leader is released, consumes every source record, refuses any loss or
unfinished syscall pair, requires the exact leader lifecycle, and reconciles the BTF-derived kernel
wait status with the root supervisor's raw `waitpid` status.

The final inert physical qualification exercised that collector end to end. It observed the exact
14-record stream as eight ordered correlated process observations:

- three paired credential syscalls: `setgroups`, `setgid`, and `setuid`;
- one leader `exec`;
- three paired loader-`mmap` syscalls; and
- one leader `exit` carrying the BTF-derived raw kernel wait status.

All records came from the inert fixture constrained to CPU 1 even though the single tracepoint-wide
perf attachment was anchored on CPU 0. Producer drops, consumer discards, pre-release events, and
host-observed raw frames were all zero. The leader executed exactly once; its kernel and supervisor
wait statuses were both exactly `0`.

This closes the process collector's arm-to-finish ownership and lifecycle-reconciliation gap. It
does **not** close protected root-service integration or the package-detection gate. The collector
is still crate-private and is not yet adapted into `LinuxVzPackageRootSensorServiceCollectorV1`.
It also drains its bounded ring only at finalization; arbitrary or noisy package workloads require
continuous draining while the leader runs. File/fanotify evidence, filesystem diff, network
correlation, an authenticated composite evidence envelope, execution-runtime integration, inert
npm/wheel/sdist scenarios, benign controls, and malicious regression all remain open. The July
malicious-package score remains **7/11 (63.6%)**.

## Safety boundary

No package and no malware sample ran. The only executed guest payload was the already-qualified,
purpose-built inert fixture. The final run used a fresh disposable Linux VZ guest on the approved
cloud Mac with:

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

## Collector contract

The Linux collector has explicit `Armed`, `LeaderAttached`, `Finished`, `Aborted`, and `Faulted`
states. Its stable fail-closed reasons distinguish unsupported platform, invalid configuration or
state, producer failure, invalid process stream, a pre-release event, invalid leader lifecycle,
and terminal mismatch.

Arm accepts only a nonzero cgroup ID, a power-of-two ring capacity from 64 KiB through 16 MiB, and
at most 65,536 source events. Before release, the collector drains once and requires no event, no
drop, no discard, and source sequence zero. Any violation faults the collector and tears down the
producer and correlator.

Finish is callable only after the protected caller has independently proved the cgroup empty and
reaped the leader. It drains the ring in bounded batches, ingests every record into the correlator,
and completes only if source sequence, drop count, discard count, and syscall pairing are exact.
It retains:

- the complete correlated stream;
- leader PID, exec count, first-exec time, and exit time;
- separate exact kernel and supervisor raw wait statuses;
- runtime BTF digest and `task_struct.exit_code` byte offset;
- all five tracepoint-format digests;
- online CPUs and the attachment CPU; and
- explicit complete-coverage and zero-loss state.

The exact leader must have at least one exec and exactly one exit. Exec and exit timestamps must be
inside the supervisor's monotonic interval, exec must precede exit, and the kernel raw wait status
must equal the supervisor raw wait status byte-for-byte. This preserves the Linux signal core-dump
bit rather than reducing the result to only an exit code or signal number. Dropping or aborting an
unfinished collector tears down its protected producer and correlator.

macOS remains platform-closed: it can define and test the contract but cannot arm the Linux root
collector.

## Strict host evidence

Canonical guest evidence schema v5 changes the qualification from a standalone probe composition
to `collector_mode = root_bpf_ring_correlator`. The strict Mac decoder additionally requires:

- `pre_release_event_count = 0`;
- `leader_exec_count = 1`;
- `process_collector_coverage_complete = true`;
- attachment CPU `0`, fixture CPU `1`, and observed event CPUs `[1]`;
- source sequence `1..14` and source-event count `14`;
- zero producer drops and consumer discards;
- exact BTF, tracepoint-layout, leader, timing, and terminal fields;
- package execution, malware execution, and sync-back all false; and
- canonical JSON with no duplicate or unknown fields.

The versioned decoder rejects replay of the preceding standalone schema and rejects collector-mode,
coverage, CPU, loss, BTF, wait-status, unsafe-execution, duplicate, and noncanonical rebinding.

## Physical qualification

The final strict host verifier exited `0` with canonical `status: "ok"`. It bound:

- collector mode `root_bpf_ring_correlator`;
- zero pre-release events and exactly one leader exec;
- complete process-collector coverage;
- tracepoint perf attachment CPU `0`;
- inert fixture CPU `1` and observed event CPUs `[1]`;
- source sequence `1..14`, 14 source events, and eight correlated observations;
- cgroup ID `21` and fixture PID `387`;
- runtime BTF SHA-256
  `d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb`;
- `task_struct.exit_code` byte offset `1964`;
- kernel and independent `waitpid` raw wait status `0`;
- zero dropped and discarded records;
- zero host raw frames; and
- a fully stopped disposable VM.

The canonical guest evidence was 1,718 bytes with SHA-256
`0aff3fb4876276f39e7a8d4c8a67fc8a4c54122d8aed5797c6e9aba04d726564`. The sanitized serial
transcript was 2,566 bytes with SHA-256
`d6a354dd88ba204eefe0e072fb67bc0363e7a3bb8ade7f1647514a2dbf54076d`.

Exact final inputs were:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 10,148,959 | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Guest init | 1,750 | `6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Static root-collector inert probe | 661,328 | `0cbfbb8ea9626d8f3725d6676340b3ff55ebf44446f14a48642ea8a816aa3f54` |
| Previously qualified inert fixture | 371,432 | `c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6` |
| Canonical overlay CPIO | 1,035,264 | `6856f4ed247ff0979e82c3c9c4bc08c3ac5b31346fa1d5774d2700dc6cc59842` |
| Deterministic gzip overlay | 542,802 | `b3fcdb695b771d9df827af445835da0447483f72384068b6ebf3277fa7be9138` |
| Combined qualification initramfs | 10,691,761 | `a1b8a43e5fd660d6e78d31fd2266ae4dfe9011379eb4d2bff31d4713ac99ef89` |
| Strict entitled Mac verifier | 2,821,008 | `ad9624e87ca9e78ba5aec87de05da999d237cc378c1a19afaafd639eda05d136` |

The verifier's signature was valid and carried only the macOS virtualization entitlement.

Runtime tracepoint-format SHA-256 identities were:

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
- Static aarch64-musl final-source rebuild through `cargo zigbuild`: reproduced the physically
  qualified 661,328-byte probe and its exact SHA-256.
- Release Mac verifier build, ad-hoc virtualization-entitlement signing, and strict signature
  verification: passed.
- Exact root-collector physical inert qualification: passed.
- Formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Root process collector | `d14deac3b22c26188f034884fc7be4723627918965355c97a5f36f8d14e7c332` |
| Root-collector inert probe | `f5b4f3176072281fd52d416c0f57ba746e1702748a1a686cef6ab15a73d12c82` |
| Strict Swift evidence decoder | `7407adcb9d15b6bf089e32c0c8ad9e9f6cdd2af17530c6c534800687dbaeb8f4` |
| Strict Mac verifier | `2ab76c996b9758a5b71777c34c4c516060c9b8185b07ac69a21ba11f7347ece9` |
| Swift decoder tests | `8beb3fa81408ef5b75acb6e602830e8546c80413cdf88b8747a145c867b6cc70` |

## Next step

Wire this collector into `LinuxVzPackageRootSensorServiceCollectorV1` behind the protected
arm/leader-attached/finish service lifecycle, and drain the ring continuously while the package
leader runs. Convert the completed correlated stream into the existing typed process evidence and
global correlation without trusting package-controlled input. The composite must remain incomplete
until protected file/fanotify and network collectors, health/loss accounting, and an authenticated
scenario-bound envelope are all present.

Only after that composite passes inert npm, wheel, and nested-sdist scenarios should benign controls
be scored. Restricted malicious regression remains a later, separate cloud-Mac lab gate; it does
not belong in this collector checkpoint.
