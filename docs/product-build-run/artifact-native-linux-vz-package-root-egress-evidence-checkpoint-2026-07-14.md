# Artifact-Native Linux VZ Package Root-Egress Evidence Checkpoint

Date: 2026-07-14

Status: cgroup-egress observations are canonical root network evidence and receipt-bound; one exact
schema-v16 inert run passed physically on the approved cloud Mac; package execution and broad
network coverage remain open

## Outcome

WhoaThere now carries the protected cgroup-`SKB` packet source into the canonical package root
network payload instead of leaving it only in the inert qualification wrapper. Schema
`whoathere.linux_vz_package_root_network_evidence.v2` binds redacted packet observations alongside
the existing `connect` and `sendto` intent records. It records packet-collector coverage and exact
drop/discard counts without serializing packet bytes or raw network addresses.

The package root-evidence receipt is now
`whoathere.linux_vz_package_root_evidence_receipt.v2`. Its domain-separated signature input binds
the canonical network payload plus the egress observation count, packet-coverage bit, and
drop/discard counts. Missing packet coverage or any packet loss makes the claims unsignable. This
receipt update is implemented and unit-tested, but the physical inert probe does not yet exercise
the production guest signer or host-composed `EvidenceEnvelope`.

A fresh schema-v16 physical run accepted exactly one redacted root-network egress observation for
the selected IPv4/UDP packet. The observation matched the protected source record field for field,
and its normalized digest matched the independently retained host frame. The run returned exit
`0`, canonical `status: "ok"`, and `vm_stopped: true`.

This is a telemetry/evidence subgate. No npm or PyPI package and no malware ran, and the July
malicious-package score remains **7/11 (63.6%)**.

## Canonical root-network v2 contract

Each egress observation binds:

- allow/block decision and IPv4/IPv6/unsupported protocol classification;
- exact action cgroup, monotonic timestamp, source sequence, and CPU;
- packet and retained-prefix lengths, prefix-truncation state, and packet-prefix SHA-256;
- ingress and egress interface indexes and raw `skb` protocol;
- the domain-separated normalized packet-correlation SHA-256 when the complete supported packet is
  available; and
- explicit wire/GSO availability, wire length, GSO segment count, and segment size.

The decoder is strict and canonical. It rejects:

- cgroup or time-window rebinding;
- gaps, reordering, duplicate correlation digests, zero sequences, and non-increasing timestamps;
- protocol labels inconsistent with the raw `skb` protocol;
- impossible packet/prefix lengths or truncation claims;
- missing or protected-binding-reused hashes;
- a correlation digest equal to the separately domain-bound prefix digest;
- a supported allow without a complete correlation digest;
- forged wire/GSO availability or nonzero unavailable values; and
- any coverage upgrade, drop/discard count, raw address serialization, or unknown field.

The payload continues to state the known gaps honestly. `guest_intent_coverage_complete`,
`host_frame_correlation_complete`, DNS, HTTP, and composite network coverage all remain false, and
the unobserved list remains `dns_intent`, `guest_intent_syscalls_beyond_connect_sendto`,
`host_frame_correlation`, and `http_observation`.

## Physical result

The approved cloud Mac ran source commit `04759c7`. The diskless guest had no root disk, directory
share, public/external route, package execution, malware execution, or sync-back path. The only
workload was the fixed inert package-sensor fixture under UID/GID `65534`.

The canonical evidence set was:

| Evidence | Count / bytes | SHA-256 |
| --- | ---: | --- |
| Root process | 18 source events, 10 observations / 6,303 | `f16b8ca6b5e4da9364dac30a64b3df88e7a52e399b393ae1ecf4abc640b68d88` |
| Root file | 12 source events, 1 diff / 6,372 | `7d9061c57261d22269169e671031008ffc9d07dd7c3a8ddc657e4f8faaac8dd0` |
| Root network v2 | 2 intents, 1 egress observation / 3,211 | `f76d0c58492a6110e126b7bed3e311930c546ff063a48283bb2513abe3ba6bf1` |
| Outer schema-v16 evidence | 6,772 | `7a83110d7472b8d9d263238feef3dde294f7a531eca1d2ab4822f4f247f0a5a2` |

The exact egress observation was:

| Field | Value |
| --- | --- |
| Source sequence / CPU | `1` / `1` |
| Decision / protocol | `allow` / `ipv4` |
| Packet / retained prefix | `44` / `44` bytes |
| Egress / ingress interface | `2` / `0` |
| Prefix truncated | `false` |
| Wire/GSO metadata available | `false` |
| Packet-prefix SHA-256 | `6e3f37b9eb5528a2957f5371bbbf6085257f9a3c8245f92e4bbb1c44cbc94479` |
| Normalized correlation SHA-256 | `a3fe695e7b00436dea508e10a7d2af2d9dc526dcfc2596b92fdcc17809c1e7fd` |

The independent host collector retained one checksum-valid frame with source port `36678`,
destination port `40553`, and a 16-byte UDP payload. Its exact frame SHA-256 was
`fccdedf99f1bb748198d03095edf9ca2542290008cd03d6f0a51fc633fceda2f`; its canonical selected-frame
evidence SHA-256 was `633839286dfcd2f609c7452f6b6742d569e389023fe36c4b1c11cfd8f6e997b1`.
Selected guest/host correlation was true while broad host-frame coverage remained false.

Process and egress BPF drops/discards, fanotify overflow, and host frame drops/truncations were all
zero. Process source sequences were contiguous from `1` through `18`. The file collector retained
its known procfs gap rather than claiming global mount coverage.

## Reproducible measured artifacts

The aarch64 guest binaries were cross-built from `04759c7`. Two canonical CPIO constructions, two
deterministic gzip constructions, and both final initramfs files were byte-identical before launch
and remained so after VM stop.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Qualified base initramfs | 10,148,959 | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Guest init | 2,367 | `2c5337b33d0763cb516de55a00026a27e8833c7ab91775017d2fbf42a4a5bb0d` |
| Static package-sensor probe | 1,690,064 | `342204ac6e3f98669adcffbd2b4d909c6d9dc4977d44c0c3efac448247e4fdbf` |
| Static inert fixture | 381,664 | `2b1e82f167eee140ed2902615eee34ad3bf4f3311c43184a1c83bc40d39e4f02` |
| Canonical overlay CPIO, both builds | 2,075,136 | `41e43b65dc01e8d615216efb988420a1d912bec4f4b11cec6d630505962a2ca6` |
| Deterministic gzip overlay, both builds | 1,003,522 | `896a5da79ed4bfdfcecc4d04373b14f9463d8185e74060bc5f22c1f979352f3b` |
| Final initramfs, both builds | 11,152,481 | `53ab0bae8dad958e224aab0b0700f490f863522e9334a45aae5b1296b07cbc46` |
| Strict entitled host verifier | 3,312,928 | `9bed783416666dd2eb5469b3aac5ce5e3ae4722890732e9fe520fd028bc8683a` |
| Sanitized serial transcript, untracked | 7,660 | `1de2ff5413c0f0c4e91e09e325eb8a2d4690a97f58c47861fa999a05f416abf9` |

The host verifier had a valid strict code signature and only the macOS virtualization entitlement.
Post-stop checks found no verifier process and no remote repository changes.

## Validation

- Repository-wide `cargo test --manifest-path whoathere/Cargo.toml`: passed, including the 222-test
  `whoathere-macos-vm` library and all binary, integration, and documentation suites.
- `cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check`: passed.
- Native `cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings`: passed.
- Linux/aarch64-musl package-wide Clippy with warnings denied: passed.
- `swift test --package-path whoathere/helpers/macos-vm-helper`: 213 passed.
- Strict physical qualification: exit `0`, `status: "ok"`, evidence valid, selected host
  correlation complete, image identity stable, VM stopped.

## Remaining gate

This closes the canonical guest egress-evidence handoff, not AN-504, AN-506, or the package-runtime
gate. Next work is:

1. wire the protected root sensor observer and typed execution sequencer into the production root
   service without converting canonical evidence back into the older synthetic payload shape;
2. sign root receipt v2 in the measured guest and independently verify it on the host;
3. compose guest evidence with the selected host frame, VM stop, image identity, and clone
   destruction in a host-authenticated envelope;
4. physically qualify purpose-built inert npm tarball, wheel, and nested-sdist scenarios; and
5. add DNS, TCP/IPv6, segmentation/retransmission, additional egress interfaces, and protected
   HTTP(S) cases before broad network claims.

Only after the complete inert package path and benign controls pass should the separate restricted
malware-lab approval be requested. Until then, containment remains credible, but broad npm/PyPI
malware detection is not useful or release-ready.
