# Artifact-Native Linux VZ Ordered Process-Evidence Checkpoint

Date: 2026-07-11

Status: the physical Linux VZ guest emits one canonical, ordered, cgroup-bound process-evidence
payload that independent Swift and Rust validators map into the existing authenticated guest-receipt
claims; live guest signing and a verified conformance receipt remain pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Process-Sensor Bootstrap Checkpoint](artifact-native-linux-vz-process-sensor-checkpoint-2026-07-11.md)
- [Authenticated Conformance-Evidence Checkpoint](artifact-native-linux-vz-authenticated-conformance-evidence-checkpoint-2026-07-11.md)

## Outcome

The root-owned sensor now records a kernel monotonic timestamp with each protected BPF observation
and requires exactly one fork, one exec, and one exit in strictly increasing order. After the inert
child exits, the guest emits exactly one canonical
`whoathere.linux_vz_process_evidence_payload.v1` record containing:

- sequences `1`, `2`, and `3` for fork, exec, and exit;
- one nonzero cgroup identity shared by every event;
- the root sensor parent as fork actor and one UID/GID 65534 child as fork subject and exec/exit
  actor/subject;
- strictly increasing kernel timestamps;
- `heartbeat_count=2`;
- `dropped_event_count=0`;
- `sensor_healthy=true`;
- `evidence_truncated=false`; and
- `descendant_teardown_complete=true`.

The host no longer treats the success markers as sufficient. The v3 boot result is successful only
if the Swift parser finds exactly one payload, proves canonical JSON and the closed key sets,
validates every relationship above, and computes its digest.

The successful physical-host payload was 664 bytes with digest:

`sha256:eb3c2b6a06d68f0a9d93546ab45763f03e828feed079af18a05d895fcf4bf5f9`

The canonical host result reported `process_evidence_valid=true`, sequences `1..3`, event count `3`,
heartbeats `2`, drops `0`, complete teardown, zero raw frames, stable image identity, VM stop, no
external route, no package execution, and no sync-back.

## Receipt-contract bridge

Rust independently decodes the serial prefix and canonical payload with the same closed semantics.
`LinuxVzProcessEvidencePayloadV1::guest_observation_claims_v1` maps the live shape directly into the
existing `LinuxVzTelemetryGuestObservationClaimsV1` fields:

- exact payload SHA-256 and byte length;
- sequence start/end and event count;
- heartbeat and dropped-event counts;
- sensor health and truncation;
- descendant teardown; and
- `observation_complete` terminal state.

The focused integration test feeds those derived claims into the existing fork/exec/exit run spec,
fresh challenge, Ed25519 guest-receipt signer, and strict verifier. Mutation tests reject duplicate
payloads, nonzero drops, timestamp reordering, and cgroup rebinding.

The standalone inspector processed the sanitized physical serial log and emitted
`whoathere.linux_vz_process_evidence_inspection.v1` with `operation=inspect_only_no_signing`,
`receipt_signing=false`, `package_execution=false`, and `sync_back=false`. This deliberately prevents
a host-side inspection tool from being confused with guest evidence authority.

## Verification

The slice passed two independent byte-identical image builds, local and remote image verification,
the successful physical-host boot, all 101 Swift helper tests, all 92 Rust macOS VM tests, the
focused cross-language receipt-bridge tests, workspace Clippy with warnings denied, Rust formatting,
and static aarch64 C compilation with warnings denied. The Rust inspector independently accepted the
sanitized physical serial log and reproduced the payload digest reported by Swift.

## Reproducible identity and custody

Two clean image builds were byte-identical and the local and remote verifiers passed.

| Object | SHA-256 |
| --- | --- |
| Image manifest v4 | `1518affa4e3e31628fc183d99bd4c5d84f753fbe9190aeb567d4b94091a12662` |
| Canonical overlay CPIO | `5d47187985256666b788e715458f392657a8af95d9fece11116372ba56bae856` |
| Combined initramfs | `0bddd589de5958faf1b445e4b80d9862be864e74619d9553c13576183ce4c005` |
| Process sensor | `7eab8b16107ecbb62dc50af03e40cc4685d53fbcc53ea0ef4c33a9f044385bc5` |

The sanitized evidence remains gitignored under:

```text
.whoathere/remote-evidence-snapshots/linux-vz-process-evidence-2026-07-11-sanitized/
```

| Sanitized evidence | SHA-256 |
| --- | --- |
| Canonical boot result | `45e167fc22519694b405fc45135530433c84d6347468aa02e391c3d44e365ed2` |
| Host preflight | `9efdf5213adb974d1e5f6ee183c639ad3fb6d9493639c97faad6cb8c30dcda5b` |
| Inert serial log | `639ddd3a4e5d9cc251e91904b7535004dbe862f4c8f2f946c443a5598b535d68` |

No package artifact, package manager, malware, credential, canary, provider identifier, remote
address, live C2, second stage, public guest route, or sync-back path is tracked.

## Claim boundary and next gate

This checkpoint proves an ordered protected bootstrap payload and an exact bridge into the existing
receipt claims. The fixed-slot bootstrap detects unexpected duplicate events by requiring each
counter to equal one, but it is not the final ring-buffer channel and does not yet prove reservation
failure accounting under load. The two heartbeats are protected runner checkpoints, not yet a
periodic liveness protocol.

Most importantly, the physical payload is not signed by a protected guest key. A synthetic test of
the signing API is not a live receipt. Therefore this still does not verify the `fork_exec_exit`
conformance case and cannot qualify the backend.

The next gate is to provision a measured root-only guest evidence key, deliver a fresh host-created
challenge and exact run spec through a bounded control channel, sign the payload-derived claims
inside the guest, and verify that receipt plus the independently signed host lifecycle receipt.
Only then can this single case contribute to the 38-case aggregate.
