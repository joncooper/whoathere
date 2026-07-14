# Artifact-Native Linux VZ Package Sensor-Payload Checkpoint

Date: 2026-07-13

Status: strict arbitrary-package process, file, and network payload schemas are implemented and
mandatory at the package supervisor boundary; the production root sensor service/observer and
authenticated package evidence remain unimplemented, so this path still cannot release a package
process

## Outcome

The prior protected-sequencer checkpoint required complete process, file, and network byte strings
whose SHA-256 digests matched one fresh, cgroup-bound correlation record. That closed splicing and
mutation at the byte level, but it did not prove that the detailed bytes had a recognized schema or
contained the behavior facts required by a detector.

This checkpoint adds a distinct package-scenario payload family and makes semantic decoding part of
the supervisor's success boundary. Digest-matching opaque JSON is no longer sufficient.

No package manager, package lifecycle, VM, or malware sample was executed while implementing or
testing this checkpoint.

## Shared binding and coverage

Every detailed stream repeats and must exactly match:

- the fresh sensor-session challenge;
- process-plan and launch-contract digests;
- action index;
- fixed cgroup name and kernel cgroup id;
- leader PID;
- package UID/GID `65534`;
- healthy sensor state, session heartbeat count, zero drops, and no truncation.

The correlation record still binds the exact canonical payload digest for each stream. The new
decoder additionally requires the declared per-stream counts to equal the correlation counts.

All process, file, and network events occupy one shared sequence beginning at one. The union must be
complete with no duplicate or missing sequence, and timestamps must increase with the global
sequence. Runtime events must fall between process start and process end. The required filesystem
diff must occur after the leader exit and before sensor teardown.

Any mismatch is a protected-sensor correlation failure. It cannot produce complete coverage,
observed-clean evidence, or a verdict-eligible transcript.

## Process payload

The process stream supports closed event kinds for:

- fork, exec, and exit;
- credential change;
- reparent and `setsid`;
- dynamic-library load; and
- signal delivery.

The exact leader must have one ordered fork, exec, and exit. Exec events carry only measured
executable and bounded-argv digests plus an item count; raw argv capture is forbidden in the
sanitized payload. Exit status and termination signal are mutually exclusive. Credential targets
and library digests remain typed so a later behavior classifier does not need to interpret free-form
text.

## File payload

The file stream supports closed event kinds and path classes for ordinary access, protected
canaries, credential/SSH material, sensor assets, persistence targets, mmap activity, and the
post-run filesystem diff. Paths are represented by scenario-bound tokens plus a coarse path class;
raw paths are forbidden in sanitized evidence.

Exactly one complete filesystem-diff event is mandatory even when no package file mutation was
observed. Its outcome is explicitly `change_detected` or `no_change`, and it must follow the leader's
terminal event.

## Network payload

The network stream may contain zero events, but its healthy zero-event coverage record is still
mandatory. When events exist, the schema preserves:

- DNS query type, including TXT, label count, wire length, and a scenario-bound name token;
- IPv4/IPv6 and TCP/UDP;
- connect, send, HTTP request, and listener intent;
- loopback, private, link-local, metadata, public, controlled-DNS, and controlled-sinkhole classes;
- blocked, sinkholed, loopback-observed, or listener-observed outcomes; and
- bounded byte counts, ports, method classes, and destination/host tokens.

The schema has no successful-public-egress outcome. It requires controlled-sinkhole-only posture,
no public route, and no raw address, DNS-name, or HTTP-host capture in sanitized evidence.

## Supervisor integration

`LinuxVzPackageObservedProcessEvidenceV1` now retains a typed
`LinuxVzPackageProtectedSensorPayloadSetV1`. Existing byte accessors return the validated canonical
payload bytes from that set, not unparsed observer output. The payload-set digest binds the
correlation and all three canonical payload digests. Both the supervisor evidence and sequence
transcript bind that payload-set digest for later guest signing.

The validation order is:

1. finish the protected observer while the empty cgroup still exists;
2. decode the exact fresh correlation record;
3. verify the three detailed payload digests;
4. semantically decode and cross-correlate all event streams;
5. remove the cgroup; and
6. construct supervisor evidence.

Failure in any step aborts the observer and returns no process evidence.

## Verification

The macOS-VM crate now has 150 passing library tests. New cases cover:

- an exact bound process/file/zero-network payload set;
- stale challenge binding, raw argv capture, and missing leader lifecycle;
- gap and post-exit-diff enforcement across streams;
- raw path and public-route rejection; and
- typed sinkholed DNS TXT intent without raw query-name or address capture.

Both native and `aarch64-unknown-linux-musl` all-target Clippy builds pass with warnings denied.
The complete workspace test graph also compiles successfully with `cargo test --workspace --no-run`.

## Remaining boundary

This checkpoint defines what the protected sensor must prove; it does not pretend to be that
sensor. The next required work is:

1. define a bounded root-only control protocol that cannot be implemented by package code;
2. implement the crate-sealed observer against a measured BPF/fanotify sensor service;
3. produce these exact canonical payloads from real inert package scenarios;
4. bind the payload-set and sequence transcript into guest and host signatures;
5. rebuild the measured runtime; and
6. run inert npm, wheel, and nested-sdist qualification inside disposable Linux VZ clones on the
   approved cloud Mac.

The transcript remains unsigned and verdict-ineligible. The current malicious-package detection
score remains 7 of 11. Restricted real-malware regression remains a later separately approved gate
and may run only on the cloud Mac inside fresh disposable Linux VZ guests.
