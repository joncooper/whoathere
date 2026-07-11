# Artifact-Native sdist Authenticated Session Checkpoint

Date: 2026-07-11

Status: a domain-separated Ed25519 guest session authenticates, stages, rehashes, cleans, and signs
an exact inert sdist staging receipt with explicit no-execution, no-sync, and no-closure-
materialization posture; freshness authority, VM launch, build-closure transport, build execution,
pip, package code, and malware remain out of scope for this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Scenario Compiler Checkpoint](artifact-native-sdist-scenario-compiler-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Mac Transport Checkpoint](artifact-native-sdist-macos-transport-checkpoint-2026-07-11.md)

## Outcome

The sdist Mac boundary now composes four additional sdist-specific layers:

1. bounded ordered control framing with an sdist-only magic and frame types;
2. a canonical nonce-bearing challenge and measured Ed25519 guest response;
3. a signed staging receipt bound to the exact sdist, fixed closure identity, and held inode; and
4. a non-executing supervisor session that authenticates, stages, checks every binding, rehashes,
   removes staging, and only then returns the receipt.

The implementation does not reuse wheel challenge, signature, receipt, or control domains. Wheel
schemas and control magic are rejected.

## Challenge and guest authentication

The canonical sdist challenge binds:

- a 256-bit nonce encoded as exact lowercase hex;
- execution-binding digest;
- Mac run-spec digest;
- fixed build-closure digest;
- disposable-clone binding digest; and
- the SHA-256 identity of the expected Ed25519 guest public key.

The signed response repeats the challenge, execution, run-spec, closure, and clone identities and
adds the measured guest-supervisor digest, runner-configuration digest, and dedicated package
UID/GID. The signature input has an sdist-only domain separator and includes the complete canonical
challenge and unsigned response. The signing seed is zeroized after key construction.

Verification requires the measured public-key digest, a non-weak Ed25519 key, canonical closed
JSON, exact expected claims, and a strict signature. Changing the closure, challenge, claims,
public key, schema, or signature fails closed.

This protocol contains nonce material but does not yet issue, persist, expire, or consume it. It
therefore proves measured key possession and exact response binding, not freshness or single-use
authority by itself.

## Signed no-execution receipt

The staging receipt signs:

- challenge, execution, run-spec, closure, and clone identities;
- exact original sdist digest and byte length;
- first held-file rehash digest and byte length;
- held file device and inode;
- fixed `artifact.sdist` name, `0444` file mode, and `0711` staging-directory mode;
- package UID/GID; and
- these literal posture fields:
  - `package_execution_enabled: false`;
  - `sync_back_enabled: false`;
  - `build_closure_materialized: false`.

Its status is `staged_no_execution_no_closure_materialization`. A closure claim different from the
challenge cannot be signed. Changing any posture or identity field after signing fails exact-claim
validation or signature verification.

## Composed supervisor ordering

The non-executing supervisor performs this sequence:

1. require the configured staging package UID to equal the signed claims;
2. read and decode exactly one sdist authentication challenge control frame;
3. sign and emit the guest authentication response;
4. receive and stage the exact sdist through the sdist guest binary channel;
5. require agreement among challenge, submission, run spec, closure, execution binding, measured
   guest key, supervisor, runner configuration, and UID/GID;
6. rehash the held read-only inode;
7. prepare the signed staging-only receipt;
8. remove the staged file and per-scenario directory; and
9. emit the receipt only if cleanup succeeded.

Binding failure after staging still invokes cleanup. Cleanup failure is retained separately from
the primary error. The session exposes no execution hook, sync option, derived-wheel return path,
or build-closure materialization path.

## Verification

| Gate | Result |
| --- | --- |
| sdist Mac integration tests | 12 passed, 0 failed |
| `whoathere-macos-vm` tests | 58 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rust formatting | passed |

The focused tests cover closure-aware Ed25519 authentication, response tampering, cross-wheel
schema rejection, bounded ordered fragmented control frames, signed false posture fields, closure
claim mismatch, the complete successful session, host-side verification of both returned frames,
cleanup-before-receipt, and cleanup after deliberate closure rebinding.

All test artifacts are generated inert tar/gzip bytes. No public network, registry, cloud Mac, VM,
guest process, build backend, setup script, pip process, Python import, package code, restricted
sample, or malware was used.

## Claim boundary and next gates

This checkpoint does not establish:

- fresh, expiring, single-use launch authority or replay prevention;
- provisioning or measurement of an sdist supervisor executable inside the stopped Mac base;
- a host helper or Swift/VZ session carrying these frames to a real guest;
- transport, staging, rehash, or provenance of each build-closure artifact;
- a root-owned fixed PEP 517 or legacy build runner;
- process, file, or network telemetry for build behavior;
- derived-wheel capture or second-clone installation; or
- any malicious or benign detection result.

The next security boundary is an sdist-specific persisted launch authority that issues a random,
expiring, single-use challenge binding and consumes it before guest authentication. After that, the
fixed build-closure artifacts need their own bounded manifest and multi-artifact transport; the
target sdist channel must not be overloaded to smuggle dependencies.

The live wheel qualification remains gated on trusted confirmation of the cloud Mac's changed SSH
host identity. Host-key verification has not been weakened.
