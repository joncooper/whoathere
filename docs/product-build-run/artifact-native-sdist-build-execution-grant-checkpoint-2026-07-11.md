# Artifact-Native sdist Build-Execution Grant Checkpoint

Date: 2026-07-11

Status: a cross-language, secret-bound, one-shot build-execution grant primitive exists; no
production route issues, sends, accepts, or acts on the grant yet

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Build-Closure Materialization Checkpoint](artifact-native-sdist-build-closure-materialization-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Build-Closure Staging Checkpoint](artifact-native-sdist-build-closure-staging-checkpoint-2026-07-11.md)

## Problem

The existing protocol authenticates the measured guest supervisor to the host. It does not yet
give the guest cryptographic proof that a later request to execute package code came from the host
that consumed the launch authority. Adding an `execute=true` field or accepting an unauthenticated
control message would therefore weaken the authority boundary.

## Capability binding

The sdist submission protocol already commits a random launch value without exposing it:

1. the issuer chooses 32 random bytes;
2. their SHA-256 is the submission’s `challenge_binding_sha256`; and
3. the execution binding hashes that challenge binding together with the exact run-spec digest.

The new primitive treats the original 32 bytes as the secret half of a build-execution capability.
The guest can hash a presented capability, reconstruct the submission execution binding with the
already authenticated run-spec digest, and compare it to the binding in the guest-authentication
challenge. A fabricated or wrong capability therefore cannot authorize execution.

The canonical `whoathere.sdist_build_execution_grant.v1` body also repeats:

- the guest-challenge SHA-256;
- execution-binding SHA-256;
- run-spec SHA-256;
- build-closure SHA-256; and
- disposable-clone binding SHA-256.

Exact equality binds the message to the fresh guest nonce and disposable clone, not merely to a
package version. The run spec transitively binds the exact target artifact, typed scenario,
measured runtime, package UID/GID, and closure.

## Burn-first verifier

The guest-side Rust verifier is an atomic, one-shot latch. It marks itself consumed before parsing,
so a malformed, noncanonical, rebound, or valid grant permanently spends that verifier. Concurrent
consumers produce exactly one winner. A valid observation contains only capability and binding
digests; it never exposes the capability bytes.

The encoder and decoder redact secret-bearing debug output and zeroize temporary capability strings,
canonical buffers, raw arrays, and owned input buffers. The Swift host encoder accepts the
capability as an `inout Data`, makes the canonical body available only through a closure, and
overwrites both buffers on every return path. Production callers must write directly to the control
channel and must not retain a closure copy.

The distinct sdist control domain now reserves frame type 4 as `BuildExecutionGrant`. Existing
production sessions still terminate after the non-executing staging receipt and never send it.

## Verification

Inert tests prove:

- a correct capability recreates the exact submission execution binding;
- a wrong capability is rejected before encoding;
- a grant is bound to the guest challenge, run spec, closure, and clone;
- an invalid first attempt burns the verifier and a second valid attempt is rejected;
- eight concurrent consumers produce one success and seven already-consumed results;
- the Rust and Swift encoders produce the same exact canonical grant digest;
- both control implementations round-trip the new distinct frame type; and
- secret-bearing debug output is redacted and host inputs are overwritten.

Verification commands completed successfully:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm --all-targets -- -D warnings
swift test
```

The Rust macOS VM suite passed 25 sdist backend tests, and the Swift helper suite passed 86 tests.
No VM, package manager, build backend, public resolver, restricted sample, or malware was used.

## Claim boundary and next gate

This checkpoint does not make package execution available. The current launch issuer discards the
random capability after committing its digest, and the production supervisor accepts no grant.
The signed staging receipt continues to require:

- `package_execution_enabled=false`;
- `sync_back_enabled=false`; and
- `build_closure_materialized=false`.

The next implementation gate is a distinct, expiring, single-use host authority that stores the
capability under mode-`0600` custody, remains pending through guest authentication and exact-byte
staging, and is atomically consumed only after the host verifies a new signed pre-execution receipt.
The guest must keep staged files inert while awaiting that grant, then materialize and hand them to
the package UID only after successful grant verification. Cancellation, timeout, or verification
failure must burn or retain the authority according to an explicit terminal policy and must never
fall through to execution.

Only after that authority transition is proven should the runner add unprivileged PEP 517 or legacy
build execution, process-group teardown, and protected telemetry. Real-malware execution remains
separately gated and unauthorized.
