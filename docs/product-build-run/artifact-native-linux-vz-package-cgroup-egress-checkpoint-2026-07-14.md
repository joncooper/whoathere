# Artifact-Native Linux VZ Package Cgroup-Egress Checkpoint

Date: 2026-07-14

Status: one exact cgroup-egress packet and its host-observed frame physically correlated with an
inert fixture on the approved cloud Mac; broad network coverage remains explicitly unqualified

## Outcome

The package sensor now observes an allowed packet at the Linux cgroup egress hook before it reaches
the existing no-forwarding macOS raw-frame sink. A strict host verifier accepted one physical run
only after proving that:

- the guest emitted exactly one cgroup-egress observation for the selected 44-byte IPv4/UDP
  datagram;
- the continuously draining host collector retained exactly one checksum-valid Ethernet frame;
- guest and host independently computed the same normalized packet-correlation digest;
- both collectors reported zero drops, discards, truncations, or overflow;
- the process, file, and network evidence remained canonical and internally bound;
- the kernel and initramfs bytes remained stable through VM stop; and
- no package, malware, external route, directory share, root disk, or sync-back path existed.

This closes the previously inferred-only denominator for the one selected transmitted UDP case.
The guest observation is now evidence that the packet reached the cgroup egress hook, and the
matching host frame proves that the selected packet also reached the host sink.

It does **not** establish broad network visibility. IPv6, TCP, GSO/segmentation, retransmission,
DNS, HTTP(S), interfaces or APIs outside the selected hooks, and loss before the host receive path
remain unqualified. The root network payload therefore continues to report broad guest-intent,
host-frame-correlation, DNS, HTTP, and composite coverage as incomplete. The July malicious-package
score remains **7/11 (63.6%)**.

## Safety boundary

No npm or PyPI package and no malware ran. The only guest workload was the existing static inert
fixture, under UID/GID `65534`, in a dedicated cgroup. It performed fixed credential, memory, file,
and documentation-address network operations and then exited normally.

The approved cloud Mac launched a fresh diskless Linux Virtualization.framework guest with one
host raw-frame sink, no forwarding or external route, no directory share, and no sync-back channel.
The run did not contact live C2 or fetch any second stage. Real-malware execution remains a separate
restricted-lab operation requiring separate approval.

## Exact correlation contract

The guest source uses a cgroup `SKB` egress BPF program filtered to the exact package cgroup. Each
accepted record binds:

- the source sequence, CPU, allow decision, IP protocol, and packet length;
- ingress and egress interface indexes;
- the complete retained packet prefix and its SHA-256 digest; and
- a normalized correlation digest used by the independent host collector.

For the qualified IPv4/UDP packet, normalization zeroes only the IPv4 header checksum and UDP
checksum before hashing. Protocol, total length, addresses, ports, payload, and every other byte
remain bound. This handles checksum computation differences without reducing the match to metadata
or an attacker-controlled marker.

The pinned kernel's cgroup `SKB` verifier rejects reads of `__sk_buff.wire_len`, `gso_segs`, and
`gso_size`, even though those fields exist in the userspace UAPI definition. Schema v15 therefore
does not fabricate them: it requires `wire_gso_metadata_available:false` and requires all three
values to remain zero. Rust and Swift decoders reject any claim that those values were observed.

## Physical result

The accepted guest observation was:

| Field | Value |
| --- | --- |
| Source sequence / CPU | `1` / `1` |
| Decision / protocol | `allow` / `ipv4` |
| Packet length / retained prefix | `44` / `44` bytes |
| Egress / ingress interface | `2` / `0` |
| Prefix truncated | `false` |
| Wire/GSO metadata available | `false` |
| Packet-prefix SHA-256 | `cecc7c2358d1b6ebb5ff2ca8436359b52ddad97c6c43622dffec33b21427a0ce` |
| Normalized correlation SHA-256 | `b765a4e662d13f313384f9ae9da5cc51d4a5bca3930c685f1e28ac58ed5e017e` |

The host collector independently retained exactly one frame with:

| Field | Value |
| --- | --- |
| Source port | `52573` |
| Destination port | `40553` |
| UDP payload | `16` bytes |
| Raw-frame SHA-256 | `c188f4a64a379c647566a88c74a07b199f2fd167aee6d1a6e07093ef36bdb79b` |
| Host network-evidence SHA-256 | `0d9f2ed88bb66dd7c823f94ae892a8067d8a802d273d3e6ddeb8b851940fba13` |
| Selected guest/host correlation | `true` |
| Broad host-frame coverage | `false` |
| Raw / retained / dropped / truncated frames | `1 / 1 / 0 / 0` |

The distinct raw-frame and normalized-correlation digests are intentional: the former binds the
exact Ethernet frame as received, while the latter binds the checksum-normalized IP packet used to
match guest and host observations.

The same run retained the following canonical guest evidence:

| Evidence | Count / bytes | SHA-256 |
| --- | ---: | --- |
| Process | 18 source events, 10 observations / 6,303 | `bca3befc9d12434f64535ee96ad85b35b206aaef9cee0fd19b5d28cd683a13af` |
| Network | 2 intents / 2,459 | `d267632cd1153975d426e94b0934125d8cf8a9f073988ecbf2f3edc6efbd3c2a` |
| File | 12 source events, 1 diff / 6,372 | `e33f5d23d8831e24741caf3957a57a86e734bc6460abde9944f6c7f4479c7819` |

Process events were contiguous from sequence `1` through `18`. Both process and egress BPF
producers reported zero reservation drops and zero discarded records; fanotify reported zero
overflow. The file collector retained its known honest limitation: procfs remains unobserved.
The network evidence retained the explicit gaps `dns_intent`,
`guest_intent_syscalls_beyond_connect_sendto`, `host_frame_correlation`, and `http_observation`.

## Qualification defects found and closed

The physical gate found one kernel-verifier mismatch that cross-compilation and unit tests could
not reveal. Work proceeded fail closed through four source identities:

1. `05d49e7` added packet correlation, but the physical run stopped before fixture release because
   a sensor producer failed.
2. `fff0698` separated process and egress producer errors and preserved the underlying errno,
   isolating `BPF_PROG_LOAD` failure `EACCES` for the egress program.
3. `da5c56b` added a bounded, failure-only, sanitized BPF verifier log. It identified an invalid
   four-byte cgroup-`SKB` context read at offset `160`, the UAPI `wire_len` field.
4. `a6d0911` removed the three verifier-forbidden wire/GSO reads and made their absence an explicit,
   strictly decoded schema fact. The deterministic final image then passed physically.

The diagnostic buffer is bounded to 64 KiB, emitted only on load failure with an ASCII-safe prefix,
and zeroed afterward. Successful evidence contains no verifier log.

## Measured artifacts

The accepted run used source commit `a6d0911`. Two clean constructions produced byte-identical
CPIO archives, gzip overlays, and final initramfses.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 10,148,959 | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Tracked guest init | 2,367 | `2c5337b33d0763cb516de55a00026a27e8833c7ab91775017d2fbf42a4a5bb0d` |
| Static package-sensor probe | 1,643,376 | `738f9329d4f827ae61dc94f4ae1474b1b15176f63bcae0891f1b2c341056f4cc` |
| Static inert fixture | 381,664 | `2b1e82f167eee140ed2902615eee34ad3bf4f3311c43184a1c83bc40d39e4f02` |
| Canonical overlay CPIO, both builds | 2,028,544 | `eaec21f9c0667bc7eb8d09ecc38ebe6a4b43100daa990864b32821cb2df6a4e6` |
| Deterministic gzip overlay, both builds | 987,010 | `e2dbd8a1d99f6a7fd5a7d08469e86201ace1dc758ed7edaed54c51710e095386` |
| Final initramfs, both builds | 11,135,969 | `df51ed34efe766488c0ddb49b4841d9e0f4053e981e9ef9f5d0add7d288fd34a` |
| Strict entitled host verifier | 3,034,752 | `c1bbc10638aaa5887249dfde3ec82c4ffd58d8951c1f5d10267203e5abbed992` |
| Sanitized serial transcript, untracked | 7,552 | `83b49efc1e6051a1d9b0efd19e922a353c46f936740f552daa3237c5f3703932` |

The canonical newc writer used for both overlay builds had SHA-256
`7c9824118597bda3d2985a9c4675a64926394439acdbda097ef3ab3708b13218`.
The final verifier had a valid strict code signature and only the required macOS virtualization
entitlement. The kernel and both final initramfs files were rehashed after the stopped run.

## Validation

- Repository-wide `cargo test --manifest-path whoathere/Cargo.toml`: passed, including 222 library
  tests and all binary and integration suites.
- `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`: passed.
- Native `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`: passed.
- Linux/aarch64 package-wide Clippy with warnings denied: passed.
- `swift test --package-path whoathere/helpers/macos-vm-helper`: 213 passed.
- Deterministic overlay CPIO, deterministic gzip, and final initramfs A/B byte comparisons: passed.
- Strict entitled physical cloud-Mac qualification: exit `0`, canonical `status: "ok"`, VM stopped,
  image identity stable.

## Remaining work

This checkpoint is a telemetry subgate, not a package-detection result. The ordered next work is:

1. carry the qualified egress observation and selected host-frame correlation through the complete
   authenticated package evidence path;
2. run the fixed execution program with purpose-built inert npm tarball, wheel, and nested-sdist
   fixtures, proving each intended lifecycle/build/import/entry-point trigger;
3. add and qualify DNS intent, additional guest egress interfaces, TCP/IPv6 and segmentation cases,
   and protected HTTP(S) outcomes without live C2;
4. score benign controls before making a false-positive or usability claim; and
5. only after the complete inert pipeline passes, request the separate restricted-lab approval for
   the 11-sample malware regression on the cloud Mac.

Until those gates close, the honest product statement remains: containment is credible and the
selected UDP path now has a physically proven guest/host denominator, but broad npm/PyPI malware
detection is not yet useful or release-ready.
