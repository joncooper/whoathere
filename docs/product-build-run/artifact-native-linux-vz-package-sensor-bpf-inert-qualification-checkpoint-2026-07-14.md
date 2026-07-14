# Artifact-Native Linux VZ Package-Sensor BPF Inert Qualification Checkpoint

Date: 2026-07-14

Status: exact lifecycle-producer slice physically qualified with an inert fixture on the approved
cloud Mac

## Outcome

The final diagnostic-free package-sensor BPF producer loaded on the pinned Linux VZ kernel and
captured one exact cgroup-filtered `exec` then `exit` lifecycle for a purpose-built inert child.
The strict host harness exited `0` with canonical `status: "ok"` after independently requiring:

- the exact kernel, initramfs, and fixture digests;
- one canonical guest evidence payload and all 12 exact capability/safety markers;
- event sequence `1..2`, event count `2`, and event kinds `["exec", "exit"]`;
- fixture exit status `0`, UID/GID `65534`, and the exact fixture digest;
- zero BPF reservation drops and zero discarded ring-buffer records;
- zero host-observed raw Ethernet frames and a host raw-frame sinkhole with no forwarding;
- no root disk, storage device, or directory share;
- stable kernel and initramfs identity after the VM stopped; and
- `package_execution=false`, `malware_execution=false`, and `sync_back=false`.

This qualifies only the selected lifecycle producer and its strict inert qualification path on one
exact measured backend. It does not qualify package detonation, arbitrary npm/PyPI detection,
selected-syscall coverage, fanotify, post-run filesystem diff, network behavior telemetry,
authenticated `EvidenceEnvelope` production, or a clean verdict. The July malicious-package score
therefore remains **7/11 (63.6%)**.

## Safety boundary

No malware or package code ran in this work. The only executed guest child was a static inert
fixture that checks its fixed argument, UID/GID `65534`, empty supplementary groups,
`PR_GET_NO_NEW_PRIVS=1`, and inherited hard and soft `RLIMIT_CORE=0`, then exits `0`.

The run used a fresh disposable Linux VZ guest on the approved cloud Mac. The VM configuration had
no root disk or directory share, and its only NIC terminated at a host raw-frame socket with no
external route. No sync-back channel existed. Any future real-malware run remains a distinct
restricted-lab operation: real malware may run only on the approved cloud Mac, inside a fresh
disposable Linux VZ guest, after the separate documented approval gate. It must never run in the
local workspace or in Docker.

## Implemented slice

### Guest producer and probe

The producer now:

- reads the running kernel's `sched_process_fork`, `sched_process_exec`, and
  `sched_process_exit` tracepoint format files, validates every required field, and binds the exact
  format-file SHA-256 values;
- accepts the kernel's legitimate signed or unsigned four-byte `__data_loc filename` declaration
  while preserving the exact measured layout hash;
- creates root-held cgroup-configuration, ring-buffer, and atomic drop-counter BPF maps;
- loads fully initialized, bounded tracepoint programs filtered to the exact disposable cgroup;
- zero-initializes the complete BPF and perf UAPI structures, including the modern program-load
  suffix through `fd_array_cnt`, signature, signature size, and keyring fields;
- attaches one program per lifecycle tracepoint through a tracepoint-wide perf attachment and
  records the online CPU set separately;
- drains the kernel ring buffer in reservation order, assigns the userspace sequence, and fails on
  malformed, busy, over-capacity, missing, reordered, duplicate, discarded, or dropped records;
- measures a root-owned, single-link, bounded fixture before fork and executes only that retained
  descriptor after the parent has placed the stopped child in the exact cgroup; and
- drops the child to UID/GID `65534`, clears supplementary groups, sets `no_new_privs`, disables
  core files with hard and soft `RLIMIT_CORE=0`, and closes all unrelated descriptors.

Linux resets the dumpable attribute to `1` when an ordinary new program image is executed, while
resource limits survive `execve`. The probe therefore keeps the child non-dumpable across the
credential-transition window but uses the production-enforced, exec-persistent `RLIMIT_CORE=0` as
the fixture-visible no-core-dump assertion. This matches the documented Linux semantics rather
than asserting an impossible post-exec dumpability state.

### Strict host decoder

The macOS conformance harness now has an explicit package-sensor qualification mode. Its decoder:

- accepts exactly one bounded, canonical JSON evidence line;
- rejects missing, duplicate, reordered, unknown, or noncanonical fields;
- binds the expected fixture digest and exact closed lifecycle/loss/safety values;
- requires the exact three tracepoint keys with distinct lowercase SHA-256 values;
- rejects any missing required marker or any failure marker; and
- combines the guest result with host-only image remeasurement, VM-stop, topology, device, and raw
  frame observations.

This host result is a qualification artifact, not the authenticated `EvidenceEnvelope` required
for verdict use. The harness was ad-hoc signed with only the macOS Virtualization entitlement.

## Final measured inputs

| Component | SHA-256 |
| --- | --- |
| Pinned Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | `sha256:9e6519ef2034469a1fbb298f4a1fb7653576eb7287600b1d9b0c75c6a2d0ae45` |
| Guest init | `sha256:6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Final diagnostic-free BPF probe | `sha256:433bce200e93ae58b6f628c1e23508361b26ec6f464c4ca35391ceccbdf386e7` |
| Inert fixture | `sha256:c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6` |
| Canonical overlay CPIO | `sha256:42706c78f1745fcd629b0c2a9496c49113a38dd4d84425176aea4b6cfc28b3b5` |
| Deterministic gzip overlay | `sha256:b5c8066fdd1060e118e37fec26fddee95099c6e6b797d4aac2eb6a6d302482d2` |
| Combined qualification initramfs | `sha256:0935bcdae68270c05d23019f51f60810a1a57753146c373b7708e2399731d10c` |
| Strict entitled host harness | `sha256:1e8b8be12980efb3d8dacebf7f04e6e674d1d0d4bae5b9eacd40de4e1ad0a8a3` |
| Sanitized final serial transcript | `sha256:8ffd5ffbceab097b9cf1282eb918a1fec80f48ac848dfedc4d0c35d45525af7e` |

The canonical overlay was `986624` bytes, its deterministic gzip form was `516921` bytes, the
combined initramfs was `12989143` bytes, and the sanitized serial transcript was `1740` bytes. The
cloud Mac reported arm64, macOS `26.3.2` build `25D2140`, and hardware virtualization support.

Key tracked source identities for this run were:

| Source | SHA-256 |
| --- | --- |
| BPF producer | `sha256:57755d836be84f27cfc2d77c507fcdfacaea61e61d67f6e88b98f65bf9b3d7d5` |
| Tracepoint parser | `sha256:91df4ea693b54927aa6cd7e3403b24735715ebbf069d80c65392f453e1a83153` |
| Inert probe | `sha256:1bdaa1445b0dc3be29ce6de88bed5f5e80b349ab5971cee5279e1f6df2fb7776` |
| Inert fixture | `sha256:2f3fc8afefceb740f2b65b58c43213faa2229cc6216992abd75288441db1c092` |
| Canonical newc writer | `sha256:46877d7b3d629134ae38505bc6bc1d57eceeaf074a2231b09d0e2de4739aea4a` |
| Strict Swift decoder | `sha256:e60db3d1e5d17d78de93163cdd94eab8bc0d667158df286b59a1e09bbff398bf` |
| Swift host harness | `sha256:419150a0545f77c829edae83b4de889b701cad4a40a4daa1730c7b95ea7965c5` |
| Cargo lock | `sha256:0635890ecb3d8b03c683983b3799e2a8fd6aa6252eb914b6e0cc227804f85b93` |

## Final sanitized result

The strict host harness emitted:

```json
{"cgroup_id":"21","directory_share_count":"0","evidence_byte_length":"892","evidence_payload_sha256":"sha256:7ce1e7e228d870ebe98e40d3c79fc908e3b5b98f03b06380329984880f29fa60","evidence_valid":true,"exit_code":0,"external_route":false,"failure_marker_present":false,"fixture_pid":"387","fixture_sha256":"sha256:c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6","image_identity_stable":true,"initramfs_sha256":"sha256:0935bcdae68270c05d23019f51f60810a1a57753146c373b7708e2399731d10c","kernel_command_line":"console=hvc0 rdinit=/init panic=0 reboot=k loglevel=6","kernel_sha256":"sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd","malware_execution":false,"missing_required_markers":[],"network_topology":"host_raw_frame_sinkhole_no_external_route","operation":"linux_vz_package_sensor_bpf_inert_qualification","package_execution":false,"raw_frame_count":0,"required_marker_count":12,"root_disk_present":false,"schema_version":"whoathere.linux_vz_package_sensor_bpf_inert_boot_result.v1","status":"ok","storage_device_count":"0","sync_back":false,"tracepoint_format_sha256":{"sched_process_exec":"sha256:f8af16db8c47534beaff9b2f477b6d309df3512f9386e0bdc079b7a5618043ba","sched_process_exit":"sha256:b04a7c7b2e0c473705fe812851c161126b0a68f3eab604e92da952a241eb5870","sched_process_fork":"sha256:84863bfaed832693cea3a4be6992a28a4d578c9bfc5cbef787a251c81a12e52f"},"virtualization_supported":true,"vm_stopped":true}
```

The bound guest evidence was 892 bytes and reported:

- cgroup ID `21`, fixture PID `387`, and fixture exit status `0`;
- exact `exec` and `exit` records with sequence `1..2`;
- online CPUs `["0", "1"]` and attachment scope `tracepoint_wide`;
- zero reservation drops and zero discarded records; and
- exact tracepoint format digests:
  - exec: `sha256:f8af16db8c47534beaff9b2f477b6d309df3512f9386e0bdc079b7a5618043ba`;
  - exit: `sha256:b04a7c7b2e0c473705fe812851c161126b0a68f3eab604e92da952a241eb5870`;
  - fork: `sha256:84863bfaed832693cea3a4be6992a28a4d578c9bfc5cbef787a251c81a12e52f`.

## Engineering findings closed during qualification

The physical gate found and closed four issues that unit and cross-compilation tests alone did not
expose:

1. The pinned kernel legitimately declares the exec `__data_loc filename` field with a signedness
   variant. The parser now accepts only the two compatible four-byte declarations and still hashes
   the exact runtime format.
2. Attaching the same tracepoint program once per CPU returned `EEXIST`; the kernel stores these
   programs in the tracepoint-wide program array. The producer now performs one tracepoint-wide
   attachment and separately records the complete online CPU set.
3. The current `BPF_PROG_LOAD` UAPI interprets bytes after `prog_token_fd` as `fd_array_cnt` and
   later fields. An implicitly uninitialized Rust padding word produced nondeterministic `EFAULT`
   before instruction processing. The full current prefix is now represented, byte-zeroed, and
   layout-tested.
4. The first purpose-built fixture correctly showed that `PR_SET_DUMPABLE=0` is reset by ordinary
   `execve`. The enforceable post-exec contract now checks inherited hard and soft
   `RLIMIT_CORE=0`, while `no_new_privs` and the dropped credentials remain directly observable.

Relevant primary references are the Linux
[trace-event ABI documentation](https://docs.kernel.org/trace/events.html),
[BPF ring-buffer documentation](https://docs.kernel.org/bpf/ringbuf.html),
[current BPF UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h),
[tracepoint BPF attachment implementation](https://github.com/torvalds/linux/blob/master/kernel/trace/bpf_trace.c),
[perf BPF path](https://github.com/torvalds/linux/blob/master/kernel/events/core.c),
[execve process-attribute semantics](https://man7.org/linux/man-pages/man2/execve.2.html), and
[resource-limit semantics](https://man7.org/linux/man-pages/man2/getrlimit.2.html).

## Validation

- `cargo test --manifest-path whoathere/Cargo.toml --package whoathere-macos-vm --lib`:
  169 passed.
- Linux/aarch64 package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Static aarch64-musl release build of the probe and fixture through `cargo zigbuild`: passed.
- `swift test --package-path whoathere/helpers/macos-vm-helper`: 200 passed.
- Strict entitled physical host qualification: exit `0`, canonical `status: "ok"`.
- The final diagnostic-free probe bytes, not an earlier troubleshooting build, were used in the
  successful physical run.

## Remaining gates

This advances the protected-telemetry work but does not close it. The next ordered work is:

1. instantiate this producer inside the root sensor service rather than the standalone inert
   qualification probe;
2. add selected-syscall production and explicit loss/overflow qualification;
3. implement protected fanotify/file collection and the independently measured post-run diff;
4. connect the already-qualified host raw-frame path to package-bound network evidence;
5. produce and verify the authenticated `EvidenceEnvelope` before any dynamic observation can
   influence a verdict;
6. rebuild and inert-qualify the complete package-execution runtime for npm, wheel, and nested
   sdist scenarios; and
7. only after the complete pipeline and benign controls pass, request the separate restricted-lab
   gate for real-malware regression on the cloud Mac.

Until those gates close, the honest product statement remains: containment is credible, and one
production-candidate lifecycle sensor slice now passes physical inert qualification, but broad
npm/PyPI malware detection is not yet useful or release-ready.
