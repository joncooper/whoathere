# Artifact-Native Linux VZ Package-Sensor Selected-Syscall Checkpoint

Date: 2026-07-14

Status: closed selected-syscall producer slice physically qualified with an inert fixture on the
approved cloud Mac

## Outcome

The final diagnostic-free package-sensor BPF producer now captures a closed set of selected arm64
syscalls in addition to the previously qualified lifecycle events. The producer loaded on the
pinned Linux VZ kernel, filtered in BPF to one exact package cgroup, and emitted paired entry and
exit records for the syscalls exercised by the inert fixture. The strict host harness exited `0`
with canonical `status: "ok"` after requiring this exact 14-event sequence:

1. `setgroups` enter and exit;
2. `setgid` enter and exit;
3. `setuid` enter and exit;
4. `exec`;
5. three `mmap` enter/exit pairs; and
6. `exit`.

The sequence was contiguous from `1` through `14`, every record carried cgroup ID `21` and fixture
PID `387`, all credential-changing syscalls returned success, each `mmap` length and result were
positive, and the address argument was zero in the emitted evidence. The run recorded zero BPF
reservation drops, zero discarded ring-buffer records, and zero host-observed raw Ethernet frames.
The strict host decoder also required stable image bytes, no root disk, no storage devices, no
directory shares, a stopped VM, and explicit false values for package execution, malware
execution, and sync-back.

This qualifies only the selected-syscall producer slice on one exact measured backend. It does not
yet connect these records to the protected root sensor service, correlate entry and exit records
into typed package-behavior evidence, qualify `connect` or `sendto` physically, or improve a
malicious-package verdict. The July actual-malware result therefore remains **7/11 (63.6%)**.

## Safety boundary

No malware or package code ran in this work. The only guest payload was the purpose-built static
inert fixture. The run occurred on the approved cloud Mac in a fresh disposable Linux VZ guest
with no root disk or directory share. Its sole NIC terminated at a host raw-frame sinkhole with no
external route, and no sync-back channel existed.

Real malware remains outside this checkpoint and may run only on the approved cloud Mac, inside a
fresh disposable Linux VZ guest, after the separate restricted-lab approval gate. It must never
run in the local workspace or in Docker, must never use sync-back, and must not contact live C2 or
fetch a live second stage.

## Implemented slice

### Closed syscall surface

The generated BPF programs accept exactly these Linux arm64 syscall numbers:

| Syscall | arm64 number | Retained entry fields | Redacted entry fields |
| --- | ---: | --- | --- |
| `setgid` | 144 | GID in argument 0 | arguments 1 through 5 |
| `setuid` | 146 | UID in argument 0 | arguments 1 through 5 |
| `setgroups` | 159 | group count in argument 0 | group-list pointer and arguments 2 through 5 |
| `connect` | 203 | socket FD and address length in arguments 0 and 2 | socket-address pointer and arguments 3 through 5 |
| `sendto` | 206 | socket FD, length, flags, and address length in arguments 0, 2, 3, and 5 | buffer and socket-address pointers |
| `mmap` | 222 | length, protection, flags, FD, and offset in arguments 1 through 5 | requested address in argument 0 |

The BPF producer rejects all other syscall numbers before reserving a ring-buffer record. It also
rejects events outside the configured cgroup before reservation, initializes every byte of each
fixed record, shares the existing atomic reservation-drop counter, and emits syscall exit results
without copying entry arguments into exit records.

Pointer-bearing arguments are deliberately zeroed in the kernel program. The userspace decoder
independently rejects an unknown syscall number, any nonzero value in a field that must have been
redacted, unexpected data or address families on these syscall records, or any nonzero argument on
an exit record. This makes pointer suppression an enforced evidence property rather than a logging
convention.

### Exact tracepoint binding

The producer now strictly parses and hashes five running-kernel tracepoint layouts:

| Tracepoint | SHA-256 |
| --- | --- |
| `sched_process_exec` | `sha256:f8af16db8c47534beaff9b2f477b6d309df3512f9386e0bdc079b7a5618043ba` |
| `sched_process_exit` | `sha256:b04a7c7b2e0c473705fe812851c161126b0a68f3eab604e92da952a241eb5870` |
| `sched_process_fork` | `sha256:84863bfaed832693cea3a4be6992a28a4d578c9bfc5cbef787a251c81a12e52f` |
| `sys_enter` | `sha256:a0a15f3bed75f08c1804f593b6164c023a85e722b8e59a0ba0b21dd66add4d5e` |
| `sys_exit` | `sha256:f8e577e78684157c4e0f22853b7b90b06119e8ff454d5873805a0857ec86fd75` |

The strict Swift decoder requires all five distinct hashes, the version-two guest evidence schema,
the exact event count and ordering, the exact syscall identities and outcomes, and all prior
lifecycle, safety, and loss invariants. The host result remains the version-one inert-boot result
because its outer topology and lifecycle contract did not change.

## Physical qualification

The final successful run used these exact inputs:

| Component | SHA-256 |
| --- | --- |
| Pinned Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | `sha256:9e6519ef2034469a1fbb298f4a1fb7653576eb7287600b1d9b0c75c6a2d0ae45` |
| Guest init | `sha256:6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Final diagnostic-free selected-syscall probe | `sha256:bc7d9cc11db99f9f9c2111574255f7bf7197808c0d07150bde1c7f256e067ec3` |
| Inert fixture | `sha256:c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6` |
| Canonical overlay CPIO | `sha256:4a8c25413eda61de21e37deae036fc5877bc3f9d45f0bbe8c30204c8fe39defa` |
| Deterministic gzip overlay | `sha256:845a7f1ec24134f34285956d641975d0b7d1cb7dee8c49c45998f339c2dcf509` |
| Combined qualification initramfs | `sha256:a8830cb1ca5d338567a636c2a4f97803ede0245da102d40f66350f783234c2b3` |
| Strict ad-hoc-signed host harness | `sha256:b0d1b42e8346a7ff6d64757278e16308efc89f1b3c560a872f54a136d1fc8892` |
| Sanitized serial transcript | `sha256:927364e4c4a0725725dc4508c664444b6beb674c5a5840abc691e748a204d8c2` |

The canonical guest evidence payload was `1233` bytes with SHA-256
`sha256:960c78482f54a3dced9011139095c3c4e7ba12f1f2a8d75a4fda34ab67cce87a`.
The sanitized version-one serial transcript was `2081` bytes. The cloud host reported arm64,
macOS `26.3.2` build `25D2140`, and hardware virtualization support. The guest ran Linux
`6.18.35-0-virt` with online CPUs `0` and `1`; the producer attached once per tracepoint at
tracepoint-wide scope.

Key tracked source identities for the successful run are:

| Source | SHA-256 |
| --- | --- |
| BPF producer | `sha256:326ca64c922d171f742315b4bec01018aea7a5ef016428737f2d05aa50f3f8d5` |
| Inert probe | `sha256:6b467035ffc7762da3281e03ed116ec7b370cebcce4eebbf866892e4abd80511` |
| Event-stream decoder | `sha256:04cc88413d78f66416769e055e63899810fea2766008723b1cce917fd95fa437` |
| Strict Swift host harness | `sha256:0787891667660579346822574cad45306513ea96ea8fb6cd98a939f83f16266c` |
| Strict Swift evidence decoder | `sha256:dfae945c0a340e8a322986d5ed0fe87b945e0dec94e9af4c10209829a7ebe0a5` |
| Swift decoder tests | `sha256:d09d3fc4d53bac12728f0ce2ebb87ca117c4e86b61c3793d4c28d9f5b895e069` |
| Cargo lock | `sha256:0635890ecb3d8b03c683983b3799e2a8fd6aa6252eb914b6e0cc227804f85b93` |

The first strict-sequence run failed closed with zero emitted frames and a stopped VM because the
fixture's runtime linker performed three legitimate `mmap` calls after `exec`, not one. A temporary
typed diagnostic exposed only event kind, syscall number, result, and sequence; it did not expose
raw arguments. That diagnostic was removed, the exact 14-event contract was encoded, and the final
diagnostic-free source and binaries were rebuilt before the successful qualification above.

## Validation

- Rust package-sensor library tests: 171 passed.
- Complete Rust workspace test suite: passed.
- Native workspace `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64 package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Static aarch64-musl release build of the final probe through `cargo zigbuild`: passed.
- Complete Swift helper suite: 200 passed.
- Strict entitled physical inert qualification: exit `0`, canonical `status: "ok"`.
- `git diff --check` and formatting checks: passed.

## Claim boundary and next work

The result advances telemetry engineering, but it does not make WhoaThere a trustworthy evil
npm/PyPI package detector yet. In particular:

- the standalone probe, not the production root service, owns the producer;
- there is no per-thread syscall entry/exit correlator or typed conversion into process, file, or
  network evidence;
- `connect` and `sendto` have unit-tested, warnings-denied cross-compiled BPF shapes but have not
  passed a physical inert sinkhole test;
- fanotify/file telemetry, independently measured post-run filesystem diffing, network
  correlation, and explicit overflow/loss qualification remain open;
- no signed `EvidenceEnvelope` can carry these observations into a verdict; and
- no malicious or benign package was executed in this checkpoint.

The next ordered work is to instantiate the producer in the protected root service, add exact
per-thread entry/exit pairing and typed evidence conversion, physically exercise `connect` and
`sendto` against the inert host sinkhole, and then implement the protected fanotify/diff/loss
paths. Only after the complete signed pipeline, benign controls, known malicious corpus, and
held-out gates pass should the project claim useful npm/PyPI malware detection.
