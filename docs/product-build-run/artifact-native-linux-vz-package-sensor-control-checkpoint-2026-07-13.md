# Artifact-Native Linux VZ Package Sensor-Control Checkpoint

Date: 2026-07-13

Status: a concrete crate-sealed package observer and bounded root-only sensor-control client are
implemented and cross-compiled; the corresponding root sensor service and event collectors are
not implemented, so this path still cannot connect to a sensor or release a package process

## Outcome

The protected supervisor previously required a sealed observer, but the crate exported no
production implementation. This checkpoint adds the first implementation:
`LinuxVzPackageRootSensorObserverV1`.

The observer can be constructed only with a fully qualified telemetry backend. It retains and
binds the exact qualified-backend, guest evidence signer, protected sensor/BPF bundle, and
sensor-configuration digests. Those component identities are now preserved when qualified backend
records are created or decoded; callers cannot substitute arbitrary component digests at observer
construction.

This is a control-plane checkpoint, not a working sensor. The root service that receives the
protocol, loads the measured BPF/fanotify collectors, and produces package-scenario events remains
to be built. No package manager, package lifecycle, VM, cloud host, or malware sample was invoked
while implementing or testing this checkpoint.

## Root-only channel

On Linux, the observer takes ownership of an already-open Unix stream descriptor and rejects it
unless all of the following hold:

- the runner's real, effective, and saved UID and GID are all root;
- the descriptor is a root-owned, root-group Unix `SOCK_STREAM` with close-on-exec set;
- Linux `SO_PEERCRED` reports a distinct root peer process with PID greater than one; and
- the peer acknowledges the exact qualified sensor components and a fresh random session
  challenge before any action can be armed.

Every frame has a fixed 60-byte header containing an eight-byte magic value, protocol version,
closed frame kind, strictly increasing sequence, bounded payload length, and SHA-256 of the exact
payload. JSON control messages use the repository's canonical JSON profile and closed schemas.
Control messages are capped at 256 KiB; correlation is capped at 64 KiB; each detailed evidence
stream is capped at 4 MiB; and reads and writes have ten-second deadlines.

The frame digest detects corruption and byte mutation. It is not described as cryptographic peer
authentication. The current channel trust comes from the root privilege boundary, peer
credentials, and exact measured-component binding; guest and host signatures remain a separate
required gate.

## Fail-closed state machine

The observer accepts only this sequence:

1. **Open session.** Bind the fresh challenge, package UID/GID `65534`, all measured sensor assets,
   no public route, and no sync-back. A root peer must prove it is ready and that no previous
   session remains.
2. **Arm.** Independently verify the exact cgroup descriptor is root-owned cgroup v2 with a
   nonzero inode, then transfer that held directory descriptor with `SCM_RIGHTS`. The service must
   echo the exact launch contract, process plan, action, cgroup name and kernel cgroup ID, and must
   report process/file/network sensors armed, heartbeat started, and zero BPF drops.
3. **Correlate leader.** After the supervisor adds the blocked child to the cgroup, require the
   service to verify `/proc` membership and the exact leader PID while the child remains blocked.
   The supervisor cannot release package code until this acknowledgment succeeds.
4. **Finish.** After descendant teardown and cgroup-empty proof, require correlation, process,
   file, and network evidence as four separate frames in that exact order. A final acknowledgment
   must bind every byte length and SHA-256, healthy sensors, at least two heartbeats, zero dropped
   events, complete descendant and sensor teardown, cgroup presence during finalization, cgroup-FD
   release, no public route, and no sync-back.
5. **Abort.** On any failure, request teardown without evidence emission. Successful abort is
   idempotent and requires sensor teardown and cgroup-FD release. An unusable channel or failed
   abort becomes a protected-sensor teardown error, never process evidence.

The receiving service must also treat EOF, timeout, malformed input, or a runner disconnect as an
automatic abort: stop collectors, release the duplicated cgroup descriptor, discard the session,
and emit no abort evidence. This requirement covers failures after `SCM_RIGHTS` transfer but before
the client receives an acknowledgment.

Wrong states, reordered or repeated frames, noncanonical payloads, unknown fields, identity or
cgroup rebinding, digest/length changes, unhealthy collectors, drops, missing heartbeat, public
routing, sync-back, or incomplete teardown cannot return a protected sensor output. The supervisor
still performs the independent semantic decode and cross-stream validation added in the prior
sensor-payload checkpoint.

## Verification

Verification used source-level compilation and inert deterministic tests only:

- all 156 `whoathere-macos-vm` library tests passed;
- new framing tests cover exact round trip, redacted debug output, magic/version/kind/digest
  mutations, zero sequence, wrong or trailing lengths, payload limits, noncanonical JSON, strict
  decimal forms, and invalid sensor identities;
- native all-target Clippy passed with warnings denied; and
- Linux/aarch64-musl all-target Clippy passed with warnings denied, including root credential,
  cgroup-v2, `SO_PEERCRED`, `SCM_RIGHTS`, observer-state, and teardown code.

The Linux implementation was cross-compiled, not executed. A passing compile does not demonstrate
that a service exists, that a collector sees real behavior, or that dynamic detection improved.

## Remaining boundary

The next required work is:

1. implement the measured root sensor service that receives this exact protocol;
2. attach cgroup-filtered process/network BPF collectors and protected file observation plus the
   mandatory post-run filesystem diff;
3. emit the existing canonical package process/file/network payloads from inert executions;
4. bind the payload set and sequencer transcript into guest and host signatures and an authenticated
   `EvidenceEnvelope`;
5. rebuild and independently qualify the exact Linux/aarch64 runtime; and
6. run inert npm CI=false/true, wheel, and nested-sdist workflows in fresh disposable Linux VZ
   clones on the approved cloud Mac before any restricted regression.

The malicious-package detection score remains 7 of 11. Real malware may run only on the approved
cloud Mac, only inside a fresh disposable Linux VZ guest under the restricted lab workflow, and
never with sync-back, live C2, or live second-stage fetching.
