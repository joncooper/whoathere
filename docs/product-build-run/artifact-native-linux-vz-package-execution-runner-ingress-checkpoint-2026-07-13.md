# Artifact-Native Linux VZ Package Execution Runner Ingress Checkpoint

Date: 2026-07-13

Status: the first reproducible aarch64 runner candidate validates one protected request and exact
artifact without executing it; package-manager operations and execution-runtime qualification
remain unimplemented

## Outcome

WhoaThere now has the first separate package-execution runner binary. It is intentionally one step
short of package execution: it proves the runner can receive a closed request through a protected
process boundary, independently decode it, and rehash the exact artifact without exposing a
general command surface.

The existing physically qualified nonexecuting runtime probe is unchanged. This is a distinct
binary with a distinct identity and must eventually live in a distinct runtime image.

## Structural decoder

The runner-side decoder accepts only canonical execution requests that preserve all of these
properties:

- the fixed post-grant authority and schema;
- nonempty authority-request, signed-grant, qualification-record, artifact, scenario, runtime,
  challenge, attempt, and clone digests;
- canonical decimal lengths, UID/GID, times, and one-attempt limit;
- UID/GID 65534;
- grant verification inside its validity interval;
- scenario resource limits inside the canonical policy bounds;
- one exact read-only artifact descriptor;
- an operation compatible with the artifact ecosystem;
- validated Python module, console-entry-point, PEP 517 backend, and backend-path syntax;
- sorted, nonempty `.pth` ids where applicable;
- exact sdist tar-gzip or ZIP form;
- no arbitrary-command field;
- no public route; and
- structurally absent sync-back.

Unknown fields, noncanonical JSON, cross-ecosystem operations, malformed numeric strings, invalid
targets, and authority/network/sync upgrades fail closed.

Parsing returns a type whose `package_execution_authority_permitted()` method is false. Structural
decoding alone is not an execution capability.

## Protected Linux ingress

The candidate runner has only two accepted invocations:

- `--qualification-probe`, which emits a fixed false-authority report; and
- `--protected-request-validate`, which is Linux-only and executes no package code.

Protected validation requires all of the following before it reads the request:

- real UID/GID 65534 and the single supplementary group 65534;
- `PR_SET_DUMPABLE=0` and `PR_SET_NO_NEW_PRIVS=1`;
- a live parent whose real, effective, saved, and filesystem UID/GID values are all root;
- descriptor 3 as a read-only pipe or socket;
- descriptor 4 as a read-only, root-owned, root-group, single-link regular artifact with mode
  `0444`;
- immediate close-on-exec marking for both descriptors; and
- kernel `close_range` removal of every descriptor above 4.

It then reads one bounded request, strictly decodes it, streams exactly the committed artifact byte
length from the held descriptor, rejects trailing bytes, and compares the SHA-256 digest. The fixed
success report says the request and artifact were validated but package execution and sync-back
remain false.

This parent/descriptor check is an operating-system capability boundary, not an HMAC with a
caller-chosen key. A direct package-user invocation cannot manufacture a root parent. The future
protected sensor must additionally bind the exact parent/child/cgroup lineage into signed evidence.

## Reproducible build and probe

Two clean offline `cargo zigbuild` release builds produced byte-identical stripped, statically
linked aarch64 ELF binaries:

- byte length: `909320`;
- SHA-256: `b084a17eec1fe4d64c1ba566627edcedece792a6c206af8235b059f3c88ccc26`.

The fixed probe ran in the already pinned Alpine aarch64 build container with `--network none` and
returned only:

```json
{"execution_authority":false,"package_execution":false,"schema_version":"whoathere.linux_vz_package_execution_runner_probe.v1","status":"closed_runner_candidate_nonexecuting_probe","sync_back":false}
```

The same network-disabled container verified that an invocation with no mode exits 64 and that a
root invocation of the protected mode exits 77 at the UID/GID boundary. The container was used only
to execute this fixed probe and negative ingress checks; it was not used as a detonation environment
and received no package artifact.

Rust tests cover canonical decoding, unknown/noncanonical/cross-ecosystem/elevated rejection, exact
inert npm binding, root-parent status parsing, and the fixed probe report. Native warnings-denied
Clippy and the Linux aarch64 cross-build pass.

## Malware handling boundary

Real malware runs only on the approved cloud Mac. This checkpoint used source code, synthetic
digest values, and one inert npm fixture. It did not download, inspect, unpack, transfer, or execute
any real sample, start a local VM, invoke npm or pip, or contact a network.

## What this does not prove

This is not an execution-capable runtime and does not improve the current 7/11 malicious-package
result. It does not yet:

- run npm, pip, Python imports, console entry points, or sdist builds;
- enforce cgroup wall-clock and descendant teardown around a package manager;
- capture process, file, network, or sensor-health evidence for a package scenario;
- validate a derived wheel;
- consume a real signed execution grant inside a booted guest;
- qualify any execution-runtime image; or
- create the opaque proof required for production grant issuance.

## Next gate

Add fixed, no-shell implementations for the closed npm install and wheel install/probe operations,
with package-manager argv and environment profiles selected only by the decoded enum. Then add the
sdist build/derived-wheel sequence, protected cgroup launch and teardown, bounded output, and signed
evidence. Those exact bytes must pass an inert execution-qualification suite in a fresh VZ clone on
the approved cloud Mac before any real package execution grant can exist.
