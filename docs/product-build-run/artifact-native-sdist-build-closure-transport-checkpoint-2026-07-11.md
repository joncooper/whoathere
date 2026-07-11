# Artifact-Native sdist Build-Closure Transport Checkpoint

Date: 2026-07-11

Status: a distinct, bounded, exact-byte sdist build-closure frame now exists in Rust and Swift and
passes inert host/guest transport tests; production supervisor staging and signed closure receipts
remain open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Helper VZ Route Checkpoint](artifact-native-sdist-helper-vz-route-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Cancellation Checkpoint](artifact-native-sdist-cancellation-checkpoint-2026-07-11.md)

## Outcome

The fixed sdist build closure is no longer represented only by a digest. The validated Rust macOS
run spec and Swift submission prelude retain the complete typed closure manifest:

- declaration-set digest;
- ordered normalized package name and version;
- exact artifact digest and byte length for every build dependency;
- closure digest; and
- canonical manifest bytes.

The closure byte stream is a distinct protocol domain:

- host frame magic: `WHOASCL1`;
- guest frame magic: `WHOSGCL1`;
- version and frame type: `1`;
- fixed prefix: 96 bytes;
- canonical manifest ceiling: 256 KiB;
- artifact-count ceiling: 64; and
- aggregate payload ceiling: 128 MiB.

The prefix binds manifest length, artifact count, aggregate payload length, raw closure digest, and
raw aggregate payload digest. The payload concatenates exact closure artifacts in the canonical
manifest order; declared lengths provide unambiguous boundaries.

## Authority and streaming order

Swift can construct an `AuthorizedSdistBuildClosureSubmission` only from an already-created
`AuthorizedSdistRunSubmission`. This preserves the burn-first boundary:

1. validate the target sdist header and complete typed run spec;
2. atomically consume its exact launch authority;
3. validate the separate closure prefix and repeated canonical manifest;
4. consume closure artifact bytes once; and
5. reframe only the transport-domain magic for the authenticated guest channel.

No closure payload byte is consumed before the authority and repeated-manifest checks succeed. The
reader and guest forwarder stream in 64 KiB chunks rather than buffering the aggregate payload.
Cancellation-aware reads reuse the sdist cancellation latch.

## Exact-byte checks

Both implementations verify:

- the repeated manifest is canonical and exactly equal to the run-spec closure;
- prefix closure identity equals the authenticated run-spec closure digest;
- artifact count and aggregate byte length equal the manifest;
- every artifact digest matches at its declared boundary;
- the aggregate payload digest matches;
- the transport domain is correct; and
- EOF follows the exact declared payload.

Wrong host/guest domains, closure rebinding, payload mutation, wrong source bytes, truncation, and
trailing bytes fail closed. Empty fixed closures are supported as an explicit canonical frame with
zero artifacts and the SHA-256 of an empty payload.

## Verification

The following inert checks pass:

- full `whoathere-macos-vm` Rust tests, including 19 sdist backend tests;
- full `whoathere-detonation` tests;
- full Swift helper suite: 84 tests;
- focused fragmented-reader tests for both Rust and Swift closure frames; and
- a Swift socket-pair check proving the guest frame differs from the host frame only by its domain
  magic and closes its write side after the exact payload.

No VM, package manager, build backend, public resolution, network, restricted sample, or malware was
used. The closure bytes are never unpacked, installed, imported, executed, or made visible to the
package UID in this checkpoint.

## Claim boundary and next gate

This checkpoint proves the protocol and exact-byte transport components, not a production closure
workflow. The `sdist-run` CLI does not yet require a separate closure descriptor, the production
Swift guest session still sends only the target sdist frame, and the Rust supervisor does not yet
stage, rehash, clean, or sign a receipt for the closure payload.

The next gate is to wire a fixed inherited closure descriptor into the authority-first route, send
the target and closure frames in one authenticated guest session without weakening either EOF
contract, stage the closure as root-owned inert files, independently rehash and clean it, and add a
signed receipt that proves exact closure transport while keeping build-closure materialization,
package execution, public resolution, and sync-back false.
