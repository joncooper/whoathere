# Artifact-Native Telemetry Feasibility Decision

Date: 2026-07-11

Status: macOS-native is not qualified as the bulk detection lane; a lightweight Linux guest on the
Mac is selected as the bulk-lane candidate, its shared requirements schema is implemented, and
inert conformance remains pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Phase 0 Baseline](artifact-native-phase0-baseline-2026-07-09.md)
- [Artifact-Native Threat-Model Addendum](artifact-native-threat-model-addendum.md)
- [Artifact-Native sdist Build-Execution Grant Checkpoint](artifact-native-sdist-build-execution-grant-checkpoint-2026-07-11.md)

## Decision

Do not enable package execution in the current macOS guest supervisor. Retain that backend for
exact-byte custody, native-fidelity staging, and a future Darwin-specific scenario lane. Build the
primary high-volume behavioral-detection lane as a measured, disposable Linux VM hosted by
Virtualization.framework on the Mac.

The Linux lane is selected, not qualified. It receives no execution authority until the inert
conformance gate in this document passes. This is the fallback required by `AN-007` when macOS
cannot currently prove every required telemetry class.

## Why macOS-native is not the bulk lane today

Endpoint Security is the supported macOS API for process and filesystem telemetry. It exposes
fork, exec, exit, file-open, and related events, and message sequence numbers allow a client to
detect kernel-dropped events. However, creating a client requires all of:

- the restricted `com.apple.developer.endpoint-security.client` entitlement;
- root execution; and
- user or managed TCC/Full Disk Access approval.

Apple requires an entitlement request for Endpoint Security. The current helper is not signed with
that entitlement, and no repository target or provisioning profile declares it. On the current
arm64 macOS 26.5.1 development Mac, SIP is enabled and unprivileged DTrace initialization fails with
`Operation not permitted`; DTrace is therefore not a deployable fallback for this route.

Endpoint Security’s documented socket event family covers Unix-domain IPC and XPC connection
events, not general IPv4/IPv6 connect or DNS intent. General flow and DNS interception requires a
separate Network Extension app or system extension and its entitlement/configuration lifecycle.
That may still be appropriate for a future host endpoint product, but it is not present or qualified
inside the current disposable guest image.

Framework or SDK-header presence is not readiness. The current machine has Virtualization and
NetworkExtension available and has Endpoint Security headers/libraries in the Xcode SDK, while the
release helper links Virtualization but carries no Endpoint Security or Network Extension
entitlement. Those facts support prototyping only.

Official platform references:

- [Apple: creating an Endpoint Security client](https://developer.apple.com/documentation/endpointsecurity/3259700-es_new_client)
- [Apple: Endpoint Security system extensions and entitlement request](https://developer.apple.com/system-extensions/)
- [Apple: Endpoint Security event types](https://developer.apple.com/documentation/endpointsecurity/event-types)
- [Apple: Endpoint Security dropped-event sequence numbers](https://developer.apple.com/documentation/endpointsecurity/es_message_t/seq_num)
- [Apple: Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)

## Selected Linux-on-Mac design

The candidate bulk lane uses:

- a pinned arm64 or amd64 Linux kernel and initramfs appropriate to the Mac CPU;
- one measured stopped base and one disposable clone per typed scenario;
- a root-owned immutable runner, sensor, BPF objects/maps, evidence key, and control channel;
- a dedicated unprivileged package UID with no capabilities and no access to sensor state;
- cgroup-scoped kernel observation for fork/exec/exit, credential changes, socket creation, IPv4/IPv6
  connect, UDP send, and relevant memory-mapping events;
- fanotify permission/notification events for protected file open/read/write activity, augmented for
  fanotify’s documented mmap blind spot;
- explicit BPF reservation-failure and fanotify queue-overflow counters that make coverage
  incomplete rather than clean;
- before/after process, listener, mount, and filesystem state comparisons; and
- a host-owned `VZFileHandleNetworkDeviceAttachment` connected only to a raw-frame sinkhole, with
  no bridge, NAT, public route, metadata route, or live second-stage path.

Apple documents Linux guests under Virtualization.framework. Its file-handle network attachment
passes raw link-layer frames through a host-managed datagram socket and does not require the
`com.apple.vm.networking` entitlement. That allows the host to corroborate DNS and connection
attempts independently and to answer only controlled synthetic endpoints.

Linux fanotify can report file access/open permission events and explicit queue overflow, with
known limitations that must be covered by an additional kernel sensor. The BPF ring buffer preserves
cross-CPU ordering needed for fork/exec/exit sequences, but reservation can fail; the sensor must
count every failed reservation in a protected map and sign that count.

Candidate references:

- [Apple: running Linux in a virtual machine](https://developer.apple.com/documentation/virtualization/running-linux-in-a-virtual-machine)
- [Apple: raw-frame file-handle network attachment](https://developer.apple.com/documentation/virtualization/vzfilehandlenetworkdeviceattachment)
- [Linux kernel: BPF ring buffer](https://docs.kernel.org/bpf/ringbuf.html)
- [Linux man-pages: fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html)

## Required inert conformance gate

The Linux candidate remains execution-disabled until one measured image proves all of the following
with inert programs:

1. The kernel configuration, BTF, cgroup v2, fanotify permission events, required BPF program types,
   and raw-frame host attachment are present and measured.
2. Fork, exec, exit, reparenting, double-fork daemonization, `setsid`, credential-change, and dynamic
   library events retain scenario/cgroup attribution.
3. Protected canary open/read/write/rename/delete events are observed; mmap-based access is covered
   separately; fanotify and BPF overflow injection produces an incomplete verdict.
4. IPv4, IPv6, UDP, loopback, private, link-local, metadata, and public-destination attempts are
   attributed in the guest and corroborated by the host when frames exist.
5. DNS intent is decoded by the host sinkhole; malformed or encrypted-DNS attempts remain visible as
   connection intent and never reach a public resolver.
6. Normal exit, timeout, TERM resistance, escaped sessions, reparented children, background
   listeners, sensor death, channel interruption, and VM stop all end with complete descendant and
   clone teardown or an infrastructure-error verdict.
7. The package UID cannot read or write sensor binaries, BPF maps, configuration, control sockets,
   canaries, evidence-signing material, or prior scenario evidence.
8. The signed guest envelope binds sensor/image/configuration digests, scenario and artifact
   identity, event sequence range, heartbeats, all drop counters, teardown, and limitations. The
   host envelope independently binds raw-frame sequence/drop state and VM lifecycle.

No clean or allow-capable verdict may be produced if any required sensor is absent, unhealthy,
unmeasured, unsupported, dropped, truncated, or unverifiable.

## Immediate implementation consequence

The current macOS npm, wheel, and sdist supervisors remain non-executing. The new sdist execution
grant stays a protocol primitive with no production issuer or consumer. The next code slice is the
Linux VZ backend identity/run-spec skeleton, which cannot construct execution authority until a
conformance receipt verifies.

This decision adds the closed canonical
`whoathere.artifact_protected_telemetry_requirements.v1` contract. It fixes the 16 required sensor
classes, raw-frame sinkhole topology, cgroup/kernel lineage, fanotify-plus-BPF file coverage,
guest-signed plus host-corroborated evidence, dedicated capability-free package UID/GID,
one-boot/one-scenario teardown, incomplete-on-any-gap policy, and structurally absent sync-back.
The contract has no readiness, clean, allow, or qualification field; a backend cannot make itself
eligible merely by serializing the requirements.

The follow-on [unqualified backend checkpoint](artifact-native-linux-vz-unqualified-backend-checkpoint-2026-07-11.md)
adds a cross-language measured identity whose only state is `candidate_unqualified` and whose API
always denies execution authority until a future conformance receipt constructs a distinct type.

No restricted sample, package lifecycle, package manager, VM, live network target, or malware was
executed while making this decision.
