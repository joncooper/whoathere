# Artifact-Native sdist Swift Authorized Guest Checkpoint

Date: 2026-07-11

Status: the packaged macOS helper core now has a complete consumed-authority-only, authenticated,
non-executing sdist staging protocol; VZ base verification, disposable-clone creation, helper CLI
routing, VM launch, build-closure artifact transport, and package execution remain open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Swift Protocol and Authority Checkpoint](artifact-native-sdist-swift-protocol-authority-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Authenticated Session Checkpoint](artifact-native-sdist-authenticated-session-checkpoint-2026-07-11.md)

## Outcome

The helper core now exposes `beginAndAuthorizeSdistRunSubmission`, which validates the bounded
host submission header and atomically consumes the matching authority before returning any API that
can read artifact bytes. Its `AuthorizedSdistRunSubmission` value retains the exact prelude,
consumed authority, and single-pass body reader as one object.

The sdist guest stack accepts only that authorized object. It cannot be constructed from a raw
prelude for production use. The stack provides:

- a closure- and authority-bound Ed25519 guest challenge and response;
- the distinct bounded `WHOSCTL1` control-frame domain;
- the distinct `WHOSGST1` exact-artifact binary domain;
- a signed staging receipt bound to challenge, run spec, build closure, clone, artifact, first
  guest rehash, staged device/inode, and package credentials; and
- required control EOF after the signed receipt.

The guest artifact forwarder preserves the canonical host header and exact raw artifact bytes,
changes only the frame magic, streams the body once, verifies its digest, and closes its write side.

## Authority-first construction

The intended helper lifecycle is now encoded as this sequence:

1. parse and validate the prefix, canonical header, run spec, template, closure, and backend;
2. atomically burn and validate the exact authority record;
3. construct an `AuthorizedSdistRunSubmission` only if all bindings match;
4. derive a fresh guest challenge from that authorized value and disposable-clone binding;
5. verify the measured guest's signed response;
6. forward the exact sdist in the sdist-only guest frame domain;
7. verify the signed staging receipt; and
8. require guest control EOF.

An authority failure leaves the artifact body unread. Expired, tampered, or rebound authority
records remain burned. Guest challenge construction repeats the consumed run-spec and build-closure
bindings rather than trusting caller-provided strings.

## Structural no-execution receipt

The accepted sdist staging receipt has a closed schema and requires:

- status `staged_no_execution_no_closure_materialization`;
- artifact filename `artifact.sdist`, mode `0444`, and staging directory mode `0711`;
- exact artifact digest and length on both transport and first guest rehash;
- nonzero staged device and inode;
- the bound unprivileged package UID and GID;
- `package_execution_enabled=false`;
- `sync_back_enabled=false`; and
- `build_closure_materialized=false`.

Those fields are inside the Ed25519 signature. A changed safety field, closure binding, digest,
credential, device/inode identity, or signature is rejected.

## Verification

The focused inert sdist suite now has 16 passing tests. New coverage proves:

- the authorization wrapper burns authority before exposing a body-consuming API;
- rebound authority leaves the complete artifact body unread and the authority consumed;
- the guest forwarder accepts only an authorized submission, preserves all bytes after the magic,
  is single-use, and closes its write side;
- challenge and response bind the consumed run spec and build closure;
- wrong keys, forged signatures, cross-wheel schemas, and rebound closures fail closed;
- sdist control frames reject wheel magic, unexpected types, empty bodies, and unsafe bounds;
- signed receipts reject unsafe execution, sync, and closure-materialization state; and
- a full socket-pair session completes authority, authentication, transfer, signed receipt, and EOF
  in order with all execution and sync flags false.

The complete helper suite passes 69 tests, and the packaged helper builds successfully in release
mode.

All fixtures are generated inert bytes. No VM, guest process, package manager, build backend,
network, restricted sample, or malware was used.

## Claim boundary and next gate

This checkpoint proves the helper-core guest protocol and type boundary. It does not prove that the
helper executable routes `sdist-run` through it, that a measured VZ base contains the matching
supervisor, that a disposable clone is created or destroyed, or that cancellation and VM-stop
ordering are safe.

The next slice is to add an sdist-specific measured-base and disposable-clone lifecycle, zero-NIC
VZ configuration, sdist-only CLI options including both authority id and authority-record digest,
and cleanup policy. The CLI must call `beginAndAuthorizeSdistRunSubmission` before installing a
VSOCK listener or starting the VM, then pass only its authorized value to the guest listener.
