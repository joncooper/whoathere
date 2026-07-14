# Artifact-Native Linux VZ Canonical Root Network-Evidence Checkpoint

Date: 2026-07-14

Status: canonical protected `connect`/`sendto` source payload, continuous bounded host-frame
collector lifecycle, and one selected transmitted UDP guest/host correlation physically qualified;
broader guest network intent and frame coverage, DNS, HTTP(S), protected transport, and composite
authentication remain open

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

## Selected transmitted UDP correlation follow-up

Commit `ca8bf2e1fb77538805af128e4de00df38db1b1dd` closes the selected-frame subgate
without upgrading the broader network claim. A fresh diskless Linux VZ guest loaded the measured
`virtio_net` module, resolved the single guest interface by the exact host-configured MAC rather
than an `eth0` assumption, disabled IPv6 on that interface, assigned only `192.0.2.2/24`, and
installed one permanent neighbor for the documentation sinkhole. There was no default route or
frame-forwarding path.

The unprivileged inert fixture first made the already protected TCP connection attempt to
`198.51.100.9:443`; it returned `-ENETUNREACH` before transmission. It then made one successful
16-byte UDP `sendto` carrying the fixed inert marker to the documentation sinkhole at
`192.0.2.1:40553`. The protected guest stream bound the exact `sendto` entry/exit at source
sequences `16/17`, normalized the destination to a challenge-bound token, and did not serialize the
raw address or marker in canonical evidence. The host collector independently retained exactly one
Ethernet/IPv4/UDP frame and the strict parser checked its MACs, tuple, lengths, IP and UDP checksums,
payload, guest source-port binding, and absence of any additional frame.

The physical verifier exited `0` with `status: "ok"`. The accepted result reported:

- 18 contiguous protected process events and 10 correlated observations;
- two canonical network events and one selected transmitted host frame;
- one retained frame, zero dropped frames, zero truncated frames, a healthy collector, and the
  terminal `drained_after_stop`;
- `host_udp_sendto_selected_correlation_complete: true`;
- `host_udp_sendto_broad_frame_coverage_complete: false`;
- canonical process, network, and file evidence with zero BPF or fanotify loss;
- stable image bytes and a stopped VM; and
- no root disk, directory share, external route, package execution, malware execution, or
  sync-back.

The guest root-network payload deliberately remains
`host_frame_correlation_complete: false`: it is emitted before host evidence is composed and its
field denotes broad correlation, not this one selected UDP case. The separate canonical host
evidence proves only the exact selected `sendto` correlation. This prevents a successful narrow
fixture from being misreported as complete guest-network or host-frame coverage.

Physical qualification exposed three fail-closed integration defects before the accepted run: the
package init did not load `virtio_net`, the probe assumed the interface name `eth0`, and the
Linux-only challenge constructor disagreed with the challenge already bound by the independent
Swift and Rust verifiers. Each failed run stopped the VM and left package execution, malware
execution, external routing, and sync-back false. The tracked init now requires `virtio_net`; the
probe uses bounded exact-MAC interface discovery and stage/errno diagnostics; and the conformance
challenge is one explicit canonical digest shared by guest and host.

Two independently constructed final CPIOs, deterministic gzip overlays, and combined initramfses
were byte-identical. The final initramfs was also byte-identical to the exact image that passed the
physical run.

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Source commit | — | `ca8bf2e1fb77538805af128e4de00df38db1b1dd` |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Network-capable base initramfs | 10,148,959 | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Tracked guest init | 2,367 | `2c5337b33d0763cb516de55a00026a27e8833c7ab91775017d2fbf42a4a5bb0d` |
| Static package sensor probe | 1,604,048 | `ffc2733e561c892facab1e91e90be113ea76f10e85ac87ae43861f9726d3f3f8` |
| Static inert fixture | 381,664 | `2b1e82f167eee140ed2902615eee34ad3bf4f3311c43184a1c83bc40d39e4f02` |
| Tracked canonical newc builder | 34,336 | `9d4c1457eace09c6dd2d063154ad36a8230342eec052a5a0494d25f0230a2971` |
| Canonical overlay CPIO | 1,989,120 | `5f489b877a55e4e384d10ae6e49882e4360a0f6b5499d4aac6fcc7af812ed79b` |
| Deterministic gzip overlay | 967,884 | `e78a9337895aa4dac96db199f013d6f60982d3bce86d8a49704198d574dc1ec9` |
| Combined qualification initramfs | 11,116,843 | `c45e839cbbbffba5501940c3a70809c1303e73410fccf9caef751a5ecec53f37` |
| Strict entitled Mac verifier | 3,029,920 | `4906f80aba7b55d6f88f7a071e1a372bbf472724fa18d063fcff587ab2b6373c` |
| Accepted sanitized serial transcript | 6,825 | `25e056fecb4d01832708de586be2dcda23896e692d7625d1a39c0f10a2e79309` |

Accepted canonical evidence identities were:

| Evidence | Bytes | SHA-256 |
| --- | ---: | --- |
| Strict outer schema-v13 evidence | 5,937 | `eddd15df8cd508d6e91efdb7f8be270317084520b8e7e0234a47ee76fd4b5cc6` |
| Root process evidence | 6,303 | `3afb318a2dbbdf2ff729c7e8aa82ea46cd41adde6467e55da3dbe1f7bfe73aab` |
| Root network evidence | 2,459 | `3029ad245f335dc775cd1b0e9836d1791fa019212eba18e37fa2c1eb3a96c3b3` |
| Root file evidence | 6,373 | `00f09bce79094e2ee7a77a2b49e67334b5394800b3a264e24132785fecf6f55f` |
| Selected host UDP correlation evidence | — | `b23cb70375bbf082c23a3adef923a162b3092325f81cb9cb3e99407d284c22ad` |
| Selected host frame | 58 | `850c13ee5bb314528fea65c768b9130bb984b44b7b141841dd558b20afe95db5` |

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
- Final transmitted-frame follow-up: Rust library 214 passed; Swift helper 213 passed; Linux
  aarch64-musl Clippy with warnings denied, Rust formatting, shell syntax, deterministic dual build,
  and exact selected UDP physical correlation passed.

## What remains

This checkpoint does not change the July malware score of 7/11. It does not establish broad
supply-chain detection, low false-positive friction, complete guest-network intent, broad
host/guest frame correlation, DNS or HTTP(S) observation, composite authenticated evidence, or
package-runtime readiness.

The next network work is:

1. cover and qualify guest outbound interfaces beyond `connect`/`sendto`, or move to a stronger
   protected hook that closes that gap;
2. extend the qualified selected UDP frame binding into explicit broad host-frame coverage without
   upgrading the claim while any guest network interface remains unobserved;
3. add DNS and HTTP(S) sinkhole observations with explicit encrypted-traffic limits;
4. authenticate the process/file/network composition and make any missing source fail closed; and
5. only then enable inert npm/wheel/sdist scenarios, benign scoring, and separately approved
   restricted-malware regression.
