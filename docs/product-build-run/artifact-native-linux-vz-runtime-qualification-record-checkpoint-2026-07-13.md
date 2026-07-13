# Artifact-Native Linux VZ Runtime Qualification-Record Checkpoint

Date: 2026-07-13

Status: the inert physical guest and host receipts are now represented by one canonical typed
record; the record cannot authorize package execution or sync-back

## Outcome

The successful inert cloud-Mac qualification is no longer only a documentary checkpoint. A new
Rust builder consumes the exact request, binary request and response frames, host evidence, host
receipt, and measured guest and host public keys. It emits a record only after all of these checks
pass:

1. the request frame contains the exact canonical qualification request;
2. the response contains only the fixed false-authority probe report;
3. the protected process payload is the complete healthy `fork_exec_exit` case for UID/GID 65534;
4. the guest receipt verifies against the request-bound guest key and exact claims;
5. the host evidence reconstructs to the exact six-event zero-frame lifecycle;
6. the host receipt verifies against the request-bound host key; and
7. both authorities bind the same request, clone, runtime, and structurally absent sync-back policy.

The copied-back inert physical evidence produced canonical record:

`sha256:327ff0316a72f3a5570b39979693f37c69bc5d5fd6fd9fce721d3b40b3df1036`

No VM was started and no package artifact was executed while building or verifying this record.

## Authority boundary

The record has only these capability facts:

- `qualification_state`: `fixed_nonexecuting_probe_passed`;
- `execution_runner_capability`: `not_qualified`;
- `execution_authority_issuance_permitted`: `false`;
- `package_execution`: `false`;
- `public_network_route_present`: `false`; and
- `sync_back_policy`: `structurally_absent`.

This distinction is deliberate. The current measured runner only implements the fixed
false-authority probe. Qualifying that probe does not qualify a future npm, wheel, or sdist runner.
An execution-capable runner will have different bytes and a different rootfs identity, and must pass
its own inert physical qualification before it can be eligible for a one-use execution grant.

The record is also not accepted on its JSON shape alone. The verifier strictly decodes it, repeats
both signature-verification paths, reconstructs the record from the original authenticated inputs,
and requires byte-for-byte equality. A copied or fabricated record therefore cannot substitute for
the signed evidence set.

## Implementation

The checkpoint adds:

- `linux_vz_package_runtime_qualification_record.rs`, which defines the closed schema, builder,
  decoder, evidence-backed verifier, and fail-closed invariants; and
- `whoathere-linux-vz-runtime-qualification-record`, a bounded, non-symlink-following CLI with
  separate `build` and `verify` operations.

The schema binds the qualified telemetry backend, all measured qualification-image and candidate
runtime components, both public-key digests, request challenge, clone, frames, probe, process
evidence, guest receipt, host evidence, host receipt, sensor state, zero-frame network state, VM
stop, and clone destruction.

Unit coverage rejects execution-authority or package-execution upgrades, noncanonical and unknown
fields, missing sensor health, dropped events, and incomplete lifecycle proof. The full Rust
workspace test suite passes, formatting is clean, and all-target Clippy passes with warnings denied.
The CLI also built and independently reverified the physical inert evidence-backed record above.

## Malware handling boundary

Real malware remains restricted to the approved cloud Mac lab workflow. This checkpoint did not
download, inspect, unpack, transfer, or execute any real sample. The local work used code, unit
tests, public keys, and the sanitized inert qualification evidence only.

## Next gate

Define a separately measured execution-capable runtime and a distinct execution-grant issuer.
Qualify that new runner with an inert physical probe on the approved cloud Mac, then consume
scenario-bound one-use grants for inert npm tarball, wheel, and nested-sdist cases. Keep the grant
bound to exact artifact bytes, runtime and telemetry identities, fresh challenge, unique clone,
expiry, one attempt, no external route, and structurally absent sync-back. The restricted
eleven-sample regression remains cloud-Mac-only and comes after the inert ecosystem matrix and
benign controls.
