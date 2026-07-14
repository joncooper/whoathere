# Linux VZ Package Root-Evidence Receipt Checkpoint

Date: 2026-07-14

Status: package-specific guest receipt protocol implemented and tested; root-service integration,
independent verification, host composition, and physical qualification remain open

## Result

WhoaThere now has a strict package-specific Ed25519 receipt for the protected guest's canonical
root process, file, and network evidence. The receipt binds one exact artifact and typed scenario to
the consumed one-use execution grant, qualified runtime, protected sensor identities, fresh sensor
session, one action/cgroup/leader, terminal state, evidence payload digests and lengths, health and
coverage state, and a bounded validity window.

This is not yet an `EvidenceEnvelope` and it is not a verdict. The receipt explicitly says that host
composition is required, VM destruction has not yet been observed, authoritative verdict issuance
is forbidden, and sync-back is false. With current collectors it also records incomplete network
and file coverage rather than upgrading the selected UDP result into a broad observation claim.

## Implemented boundary

The schema `whoathere.linux_vz_package_root_evidence_receipt.v1` binds:

- exact npm tarball, PyPI wheel, or PyPI sdist identity and byte length;
- package-authority request, typed scenario, dependency closure, and runtime-profile digests;
- consumed execution grant, issue/verification/expiry times, runtime qualification, and fresh
  request, grant, attempt, clone, and sensor-session bindings;
- qualified telemetry backend, guest signer, protected sensor bundle, configuration, launch
  contract, process plan, action, cgroup, root runner, and package leader;
- exact canonical root process, file, and network payload hashes, byte lengths, and counts;
- process terminal and monotonic start/end evidence, heartbeat state, zero drops, zero truncation,
  no raw arguments/paths/addresses, no public route, and no sync-back;
- each current network coverage bit and the explicit unobserved-capability list;
- guest evidence public-key digest, creation time, expiry, and a domain-separated Ed25519
  signature.

The public claims constructor accepts already decoded root-evidence types rather than unchecked
JSON. It rehashes their canonical bytes, checks the root network payload's process binding,
validates the request/grant/backend relationships, and rejects inconsistent coverage. The signer
zeroizes its input seed after deriving the signing key.

Verification checks time and key identity, requires strict canonical JSON with no unknown fields,
reconstructs the full expected unsigned claim set, and only then verifies the signature. A verified
guest receipt still exposes `host_composition_required: true`,
`authoritative_verdict_permitted: false`, and `sync_back_permitted: false`.

## Negative proofs

Tests establish that the verifier rejects:

- rebinding any evidence payload digest;
- changing the Ed25519 signature;
- a wrong verification key;
- a receipt observed before creation or at/after expiry;
- noncanonical trailing bytes; and
- an attempted upgrade from incomplete to complete coverage.

The full `whoathere-macos-vm` crate passed 217 Rust library tests. All target tests passed with
Clippy warnings denied, and formatting is clean. Tests used inert synthetic claims only. No package
or malware executed.

## Remaining gate

AN-506 remains open until all of the following are complete:

1. Pass exact authority/grant and key-lifecycle bindings into the protected root service.
2. Have the measured guest signer authenticate the receipt after the collectors finish.
3. Add a separately implemented verifier, starting with the Mac host implementation.
4. Bind host raw-frame evidence, VM stop, image identity, clone destruction, and restricted raw
   evidence references into a distinct host-signed composite envelope.
5. Prove missing, killed, stale, rebound, or forged sensors/receipts yield error or inconclusive and
   can never produce observed-clean.
6. Physically qualify the authenticated path with inert npm, wheel, and nested-sdist scenarios
   before any restricted malware regression.

The selected UDP physical pass remains valid and narrow. This checkpoint authenticates the guest
claim shape; it does not close DNS, HTTP(S), broad syscall coverage, host composition, package
scenario execution, benign scoring, or the 11-sample malicious regression gate.
