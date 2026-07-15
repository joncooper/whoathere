# Linux VZ Package Independent Host-Composite Verification Checkpoint

Date: 2026-07-15

Status: qualified evidence-key propagation, host-UDP schema-v2 parity, and independent Rust
verification of the Mac host-composite receipt are implemented and tested; protected guest-signer
integration and physical inert-package qualification remain open

## Result

WhoaThere no longer has to trust the Mac helper's self-verification of package host-composite
evidence. A separate Rust implementation now strictly decodes the canonical composite evidence,
rebuilds it from already verified inputs, reconstructs the unsigned receipt, validates freshness,
and verifies the domain-separated Ed25519 signature.

The expected host key is not selected at composite-verification time. The opaque execution-runtime
qualification carries distinct guest, host, and grant-issuer key identities into the one-use grant
context. Successful grant consumption preserves the guest and host evidence-key digests in its
typed observation. Root-receipt construction derives its guest key from that observation, while
the Rust host-composite expected binding derives its host key from the same observation.

This is a protocol and verifier checkpoint. The execution-capable runtime qualification still has
no public production constructor, and the physical guest root service does not yet emit the root
receipt. No package execution is enabled by this work.

## Host-frame schema parity

The Rust selected-UDP decoder now accepts the same schema-v2 object as Swift. In addition to the
root network evidence, process evidence, sensor-session challenge, and destination token, it binds:

- the guest cgroup-egress packet-correlation digest;
- the host frame's independently derived network-layer correlation digest; and
- exact equality between those two values.

The obsolete schema-v1 shape, correlation rebinding, a changed packet digest, dropped or truncated
frames, coverage upgrades, and noncanonical or unknown fields fail closed. The accepted object
still proves only one selected transmitted IPv4/UDP event and explicitly leaves broader host-frame
coverage incomplete.

## Independent composite verification

`LinuxVzPackageHostCompositeExpectedBindingsV1` can be constructed in production only from:

- an exact package-authority request;
- its consumed one-use execution-grant observation;
- a verified guest root-evidence receipt;
- independently decoded host selected-UDP evidence; and
- a closed Mac lifecycle with sorted digest-only restricted-evidence references.

The constructor checks the artifact, authority request, execution grant, clone, runtime rootfs,
runtime manifest, package runner, distinct guest/host keys, exact guest evidence digests, host frame,
and egress-packet correlation. The lifecycle requires VM start, terminated guest channel, stopped
VM, stable image remeasurement, clone destruction after stop, zero externally forwarded frames,
and no raw restricted-evidence paths or bytes.

The receipt verifier then requires exact canonical evidence and receipt bytes, a maximum ten-minute
validity interval, the grant-qualified host public key, and a valid CryptoKit/Rust-compatible
Ed25519 signature. It fixes the result at:

- `inconclusive_incomplete_coverage`;
- selected UDP correlation complete;
- broad host-network and composite evidence incomplete;
- authoritative verdict not permitted; and
- sync-back structurally absent.

## Cross-language proof

Swift and Rust independently construct the same canonical composite evidence:

- composite evidence: `sha256:ab65634f16bbdf22c57a4f5146fa5e7885720b9722b3a1b8cd1c2b65fb46c5ee`.

Each implementation verifies a receipt produced by the other:

- CryptoKit-produced receipt verified by Rust:
  `sha256:60e4cf6cfc353c32f34248b0240d23111a7f57b8157a16778ec122bbec3181a9`;
- Rust-produced receipt verified by CryptoKit:
  `sha256:6a45287c15812d0ad932e7558ae9c34cb4ade14bc81dbb052d23d2c952f173f0`.

The fixtures contain synthetic digests and inert canonical evidence only. They are interoperability
proofs, not behavioral detections.

## Verification

Focused Rust and Swift tests cover successful cross-language verification plus failure on:

- grant/key, artifact, root-receipt, host-frame, and packet-correlation rebinding;
- obsolete host-UDP schema, noncanonical bytes, and unknown fields;
- missing VM stop, unsorted restricted-evidence references, and forwarded frames;
- wrong host key, stale receipt, forged signature, and validity-window errors;
- coverage, verdict-authority, or sync-back upgrades.

The final qualification run passed:

- all 226 `whoathere-macos-vm` Rust library tests;
- the full Rust workspace test and documentation-test suite;
- workspace Clippy across all targets with warnings denied;
- Rust formatting checks; and
- all 218 Swift helper tests.

No VM, package, or malware executed for this checkpoint. No raw malware, packet capture, VM disk,
private host path, canary, or credential was added to tracked files.

## Remaining gate

AN-506 remains open. The next engineering slice is to:

1. carry the exact authority request and consumed grant into the protected root service;
2. construct and sign the root receipt after process, file, and guest-network collectors finish,
   without exposing the signing seed to the untrusted package supervisor;
3. transport the bounded receipt and incomplete root evidence to host composition instead of the
   older complete-legacy-payload path;
4. exercise that path physically with inert npm, exact-wheel, and nested-sdist scenarios while
   preserving no route, no share, no sync-back, stop-before-destroy, and stable image identity;
5. broaden network coverage and run benign controls; and
6. only then request separate approval for the restricted eleven-sample regression.

The July actual-malware score remains 7/11. This checkpoint improves evidence trustworthiness; it
does not detect another sample and does not justify a broader product claim.
