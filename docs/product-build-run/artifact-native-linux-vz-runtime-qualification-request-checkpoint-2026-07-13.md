# Artifact-Native Linux VZ Runtime-Qualification Request Checkpoint

Date: 2026-07-13

Status: a closed, exact-byte, non-authorizing runtime-qualification request is implemented and
independently decoded by Rust and Swift; no package-runtime VM has booted and the candidate remains
unqualified

## Outcome

The host now has a distinct request domain for qualifying the package-runtime composition. It is
separate from both the 38-case telemetry-backend qualification and the later per-artifact package
authority request. The new request permits exactly one operation: run the fixed non-executing
runtime probe under the already-qualified protected `fork_exec_exit` sensor case.

The canonical request binds:

- the qualified telemetry record, backend identity, requirements, conformance evidence set,
  kernel, qualified initramfs, protected signer/sensor, and both evidence public keys;
- exact runtime-qualification initramfs, guest agent, guest init, and module-bundle identities;
- exact candidate rootfs bytes and length, runtime manifest, and package runner;
- the fixed expected probe report;
- a fresh challenge digest and unique writable-clone binding;
- the measured package UID/GID; and
- one writable clone destroyed after VM stop, the raw-frame host sinkhole with no external route,
  zero directory shares, no public resolver, no package execution, and structurally absent
  sync-back.

There is no grant type, package artifact, package command, generic argument vector, capability, or
sync-back destination in this schema.

## Independent agreement

Rust constructs the request and verifies received bytes by strict typed decode, RFC 8785-style
canonical re-encoding, and exact rebuild from trusted inputs. Swift independently enforces the
closed key set, fixed enum values, decimal bounds, digest shapes and relationships, exact probe
report, and false authority fields before a launcher may use the request.

Both implementations reconstruct the same inert fixture with request identity:

```text
sha256:08cf56cbf44a30bd906efa2fcb72383fe2145a709ffe505cb376f4ddf83d1e0d
```

Adversarial coverage rejects:

- zero challenges and challenge/clone reuse;
- clone reuse as the candidate rootfs or qualification initramfs identity;
- candidate-runtime rebinding;
- duplicate or empty qualification-image identities;
- wrong probe-report identity;
- noncanonical and unknown-field JSON;
- open-ended operation, storage, network, share, or runner policies;
- root package identity; and
- attempts to set execution authority or package execution to true.

The focused Rust integration suite passed all four telemetry-qualification tests, Rust Clippy
passed with warnings denied, and the two focused Swift decoder tests passed. The complete Swift
suite had already passed 194 tests with the new decoder before the cross-language fixture was
tightened; the focused golden tests passed again afterward.

## Deliberate fail-closed mismatch

The protected process sensor invokes its measured target with the closed argument
`fork_exec_exit`. The current package-runtime probe accepts only `--runtime-probe` and returns exit
64 for every other invocation. The qualification request therefore cannot be satisfied by the
current candidate bytes.

Before a physical run, the runner must add `fork_exec_exit` as an exact alias for the same fixed
non-executing report, while continuing to reject every other invocation. That changes the runner,
rootfs, manifest, and clone identities, so the pinned image must be rebuilt reproducibly and pass
the independent runtime and clone preflights again. The request must then bind the new identities.

## Claim boundary

This checkpoint did not boot a VM, mount the candidate rootfs, run the probe in a guest, produce a
runtime-qualification receipt, issue a one-use package grant, run npm or pip, process a package
artifact, or handle malware. It does not improve the July malicious-package detection score.

Real malware remains restricted to the approved cloud Mac lab workflow. The next physical run is
still inert runtime qualification, not malware detonation.

## Next gate

Add the runner's closed sensor alias, rebuild and re-preflight the candidate, then build the minimal
measured qualification overlay and signed receipt. On the approved cloud Mac, boot one unique clone
with only the inert request and prove:

- exact request, image, base, clone, runner, and report bindings;
- protected process/file/network/drop/health evidence with no unexplained loss;
- one writable block device, zero shares, no public resolver, and zero forwarded external frames;
- VM stop before clone destruction; and
- no package execution grant or sync-back path.
