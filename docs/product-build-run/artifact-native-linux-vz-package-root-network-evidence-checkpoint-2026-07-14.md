# Artifact-Native Linux VZ Canonical Root Network-Evidence Checkpoint

Date: 2026-07-14

Status: canonical protected `connect`/`sendto` source payload and continuous bounded host-frame
collector lifecycle physically qualified; broader guest network intent, transmitted-frame
correlation, DNS, HTTP(S), protected transport, and composite authentication remain open

## Result

WhoaThere now derives a separate canonical root network payload from the same protected,
cgroup-correlated process collection that produces canonical process evidence. The payload is
strictly bound to the sensor challenge, launch contract, process plan, canonical process-evidence
digest, action, cgroup, root runner, package leader, and supervisor completion window.

Each observed `connect` or `sendto` event records only normalized and redacted evidence:

- event kind, address family, destination class, and port;
- a domain-separated destination token bound to the challenge, event kind, family, port, entry
  sequence, and exact raw address;
- entry/exit source sequence, monotonic timestamps, CPUs, cgroup, PID/TGID, and syscall result; and
- no raw address or pointer argument.

The encoder zeroizes the token preimage after hashing. The strict decoder rejects unknown fields,
noncanonical JSON, binding substitution, count or ordering gaps, duplicate destination tokens,
nonminimal decimal encodings, invalid destination classes, and forged coverage upgrades.

## Honest coverage boundary

The schema does not describe the current source as complete guest-network telemetry. Its exact
claims are:

- `connect_sendto_intent_coverage_complete: true`;
- `guest_intent_coverage_complete: false`;
- `host_frame_correlation_complete: false`;
- `dns_intent_coverage_complete: false`;
- `http_observation_complete: false`;
- `composite_network_coverage_complete: false`; and
- `raw_addresses_serialized: false`.

The canonical payload names every current gap:

1. `dns_intent`;
2. `guest_intent_syscalls_beyond_connect_sendto`;
3. `host_frame_correlation`; and
4. `http_observation`.

This distinction matters. Linux package code can use additional network interfaces such as
`sendmsg`, `sendmmsg`, or io_uring operations. The qualified source is complete only for the closed
`connect`/`sendto` slice, not for every guest network API.

The concrete root-service adapter now creates and retains canonical process, network, and file
payloads from one action. It still reports broad network coverage unavailable during arm and
returns a fail-closed finish error. Therefore this checkpoint cannot release a package or produce
an observed-clean verdict.

## Physical qualification

No package and no malware sample ran. The cloud Mac launched one fresh diskless Linux VZ guest with
two vCPUs, no root disk, no directory share, one host raw-frame sink, no external route, and no
sync-back path. The same unprivileged static inert fixture performed the previously qualified
credential, exec, mmap, and file operations, then:

1. attempted TCP `connect` to IPv4 documentation address `192.0.2.9:443`;
2. attempted one-byte UDP `sendto` to IPv6 documentation address `[2001:db8::9]:53`; and
3. exited normally.

The calls returned `-ENETUNREACH` (`-101`) and `-EADDRNOTAVAIL` (`-99`) before transmission. The
independent host raw-frame sink received zero frames.

The first schema-v12 diagnostic run failed closed before evidence emission because the new encoder
incorrectly required the kernel exit timestamp to equal the later supervisor completion timestamp.
It produced zero host frames and no package, malware, or sync-back activity. The binding was fixed
to require the kernel exit strictly inside the trusted supervisor window, matching the already
qualified process-evidence rule. A regression test proves that physical timing shape and rejects a
supervisor window ending before the kernel exit.

The failed diagnostic transcript was 1,013 bytes with SHA-256
`e99c0f71e6a2d9524c8804c2a487faa0ffcea08e9e68c98be1c13af555c4e8a3`.

The final strict verifier exited `0` with `status: "ok"` and `evidence_valid: true`. It bound:

- 18 contiguous process source events and 10 correlated observations;
- two exact `connect`/`sendto` events at sequences `14/15` and `16/17`;
- zero BPF drops and zero discarded userspace records;
- 57 active process-drain polls, four nonempty polls, and maximum batch size seven;
- 12 file events, 11 permission responses, one exact workspace rename diff, and zero overflow;
- the injected eight-event source-limit fault, descriptor-relative cgroup kill, 1,171-microsecond
  fault signal, and exact `SIGKILL` reap;
- zero host raw frames, stable image bytes, and a stopped VM; and
- `package_execution: false`, `malware_execution: false`, and `sync_back: false`.

Canonical payloads from the accepted run were:

| Payload | Bytes | SHA-256 |
| --- | ---: | --- |
| Root process evidence | 6,305 | `118e7eb6c3079325bcf807df2a06bf0030f1c33306305e5cc5ce642ca4aee477` |
| Root network evidence | 2,457 | `5b9fbdde46a0e0728b898c905ecf2c946a0f7ed96f2416a358d20e22c115242c` |
| Root file evidence | 6,372 | `4aee182366c4977efa65b8a09edf0fb236746786bd0bf172ee293b3c36f4fbfe` |
| Strict outer schema-v12 evidence | 5,666 | `b1e631d98e21c974065609a372620e97bcdc2decc9776dbfb0f6e4689036bf94` |

## Exact identities

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Source commit | — | `e19fb59d4348f6f09f8ea7cf16eee81cfcaac9bd` |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 12,472,222 | `9e6519ef2034469a1fbb298f4a1fb7653576eb7287600b1d9b0c75c6a2d0ae45` |
| Guest init | 2,205 | `8e4b7a709ae061f88cedaf45db55b3a9f7e94730aa4a966ed3bb5029ec12c709` |
| Static root-network/process/file probe | 1,587,224 | `81f52c69cefa8e8aebfa6fbb4ffddfd9a7fa2701f2c40f88607aafe0dcd9de6e` |
| Static inert fixture | 381,712 | `c916471f9928b9e204c41d5d8e87ab39501dd1270b921a76418ddd693e590e54` |
| Canonical overlay CPIO | 1,972,224 | `8a2833d3c21b2316071db0654fa3266b84d06873d47f2e9609dc05698fb7070e` |
| Deterministic gzip overlay | 959,954 | `0ac379f12b9753c015da8fc67f1006b4f2233e575af16903592a775514689853` |
| Combined qualification initramfs | 13,432,176 | `64e5c5d0e7eb4ed65dd5249b1510a2ad375874811e64180046fda4bbc67832d5` |
| Strict entitled Mac verifier | 2,893,296 | `5a9db734d7affda3041369c61e7944a23f09a4e56e2ba9efee1194fc9248b6f8` |
| Accepted sanitized serial transcript | 6,514 | `c86818888195494eba5bda0a494048b2ed57012e40805a1e7b81c33ed338986b` |

Two independently constructed overlay CPIOs and deterministic gzip outputs were byte-identical.
The verifier passed strict code-signature validation and carried only the macOS virtualization
entitlement.

## Continuous host-frame collector follow-up

Commit `5d0db42e4a1f23075421608a9d6e69cc1cd1c377` replaces the package qualification
harness's post-stop-only socket drain with a shared bounded collector. The collector starts before
VM launch, drains the datagram socket continuously, retains at most a configured number of frames,
and counts ingress, retention loss, and truncation separately. After the VM stops, the host requests
collector shutdown; the worker performs a final drain through `EAGAIN` before returning. Socket
errors and truncation make the sensor unhealthy. Any nonzero dropped or truncated count makes the
package qualification fail even when the socket itself remained healthy.

The same component now drives the existing 512-frame overflow conformance case, preserving that
case's explicit 64 retained/448 dropped accounting while removing its private collector copy. Four
new tests cover a clean final drain, bounded retention overflow, Darwin `recvmsg` truncation flags,
invalid configuration, and single-use lifecycle. The complete Swift suite passed 204 tests.

The cloud Mac rebuilt the strict verifier from the pushed commit. Its first launch was rejected by
macOS before VM creation because the fresh binary had not yet been signed with the virtualization
entitlement. After ad-hoc signing with the repository's minimal entitlement, strict code-signature
verification passed and the same diskless inert fixture ran successfully. The result schema was
bumped to `whoathere.linux_vz_package_sensor_bpf_inert_boot_result.v2` and reported:

- `raw_frame_count: 0`;
- `raw_frame_retained_count: 0`;
- `raw_frame_dropped_count: 0`;
- `raw_frame_truncated_count: 0`;
- `packet_sensor_healthy: true`; and
- `packet_sensor_terminal: "drained_after_stop"`.

The VM stopped, image hashes remained stable, canonical process/file/network evidence passed the
strict decoder, and package execution, malware execution, external routing, and sync-back all
remained false. This result physically qualifies continuous collection and final-drain behavior for
a non-transmitting fixture. Because both protected guest calls failed before transmission and the
host observed zero frames, it does not qualify transmitted-frame matching or allow
`host_frame_correlation_complete` to become true.

Follow-up identities were:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Source commit | — | `5d0db42e4a1f23075421608a9d6e69cc1cd1c377` |
| Signed continuous-collector verifier | 2,911,856 | `a5a8bb0f77df42dc3df95c8b6004977c333ebb905d287d15915c7b10d6b3d0ca` |
| Accepted sanitized serial transcript | 6,514 | `5167b56beba29b5c2684854d7d2569b8b647685eab02ddb28a7b08c144790862` |
| Shared host raw-frame collector source | — | `01c7f72966bb72148a12b3726ded2e044a378cce82d03b9d2e4aebe8edf91670` |
| Package qualification verifier source | — | `7846ea0c63db5140c93a3b9ce8d8dd2cf337d683944a805922914107b08d6c1a` |
| Signed conformance verifier source | — | `dec638c6395b16884482e7a1c51b40d9e876ad8fde4dec17906b779976dcf5ae` |

Tracked source identities were:

| Source | SHA-256 |
| --- | --- |
| Canonical root network evidence and decoder | `efc59236db6932b53d10780d6291c5e9e4bd4e9ccbd4bfa0c3a3ecf7a95996a2` |
| Inert physical qualification probe | `b3ab2bd4a2be95ed601392b87ddabfb0171a1d4f981c164e91c3868f38e24f71` |
| Root sensor control/composition | `e8f5b5f288780116e3f0ceedd124bb597e4838761b004768093af5249a6bffa5` |
| Strict Swift schema-v12 decoder | `d31f587f31b9981dba1a1c006ca02796d4e7650fa9a4f6f8d801864680ca4a7f` |
| Strict Mac physical verifier entrypoint | `cf6689e1a901d3f1bcd4a158dcad462c4830330e2f9d5c8e0afcc327210a1aca` |

## Validation

- Complete Rust workspace tests, integration tests, and doctests on the initial schema-v12
  candidate: passed.
- Final `whoathere-macos-vm` Rust library suite after the timing correction: 210 passed.
- Swift helper suite for schema-v12: 200 passed.
- Native and Linux/aarch64-musl package-wide Clippy with warnings denied: passed.
- Static aarch64-musl release probe and fixture build through `cargo zigbuild`: passed.
- Rust formatting and `git diff --check`: passed.
- Deterministic overlay reproduction: passed.
- Strict code-signature and virtualization-entitlement verification: passed.
- Exact inert physical qualification with zero-loss process/file continuity and injected-fault
  behavior: passed.

## What remains

This checkpoint does not change the July malware score of 7/11. It does not establish broad
supply-chain detection, low false-positive friction, complete guest-network intent, host/guest
frame correlation, DNS or HTTP(S) observation, composite authenticated evidence, or package-runtime
readiness.

The next network work is:

1. cover and qualify guest outbound interfaces beyond `connect`/`sendto`, or move to a stronger
   protected hook that closes that gap;
2. run controlled transmitted-frame fixtures and bind exact host frames to guest process intent;
3. add DNS and HTTP(S) sinkhole observations with explicit encrypted-traffic limits;
4. authenticate the process/file/network composition and make any missing source fail closed; and
5. only then enable inert npm/wheel/sdist scenarios, benign scoring, and separately approved
   restricted-malware regression.
