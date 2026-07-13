# Artifact-Native Linux VZ Package Execution-Grant Protocol Checkpoint

Date: 2026-07-13

Status: the signed burn-first one-use grant protocol is implemented and tested; production grant
issuance remains structurally unavailable until a separate execution-capable runtime passes
authenticated physical qualification

## Outcome

WhoaThere now has a Linux VZ package execution-grant wire and verifier that can represent exactly
one typed package scenario attempt. This is protocol work only. It does not make the current
nonexecuting runtime eligible to execute a package.

The grant binds:

- the exact artifact kind and SHA-256 identity;
- the complete prequalification package-authority request;
- the selected scenario plan, scenario template, and runtime profile;
- the qualified telemetry backend;
- a future authenticated execution-runtime qualification record;
- the exact execution rootfs, manifest, and package-runner identities;
- a distinct execution-grant issuer public key;
- the original request challenge plus a new grant challenge;
- one attempt binding and one unique clone binding;
- issue and expiry times capped at fifteen minutes;
- UID/GID 65534;
- `one_typed_scenario_one_attempt` scope;
- no public network route; and
- structurally absent sync-back.

The issuer signs canonical JSON with a domain-separated Ed25519 signature. The verifier requires
the public-key digest committed by the qualified execution runtime and rejects weak, substituted,
or mismatched keys.

## Burn-first semantics

The verifier atomically consumes its single attempt before it performs any other operation. This
ordering applies to:

- not-yet-valid grants;
- expired grants;
- malformed or oversized bytes;
- noncanonical or unknown JSON;
- request, artifact, scenario, runtime, challenge, attempt, or clone rebinding;
- signature failure; and
- a valid grant.

After any first call, every retry returns `already_consumed`. The consumed input buffer is zeroized,
and the signed grant byte wrapper zeroizes its storage on drop. This verifier is intended to live in
the protected single-run guest agent, not in the unprivileged package process.

## Structural non-issuance

The grant context requires an opaque
`VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1`. That type has no public constructor
in this checkpoint. A later evidence verifier must be the only production path that creates it after
an execution-capable runtime passes authenticated physical qualification.

The opaque proof must bind:

- a qualification record distinct from the existing nonexecuting record;
- exact execution rootfs, manifest, and runner identities matching the package request;
- the exact qualified telemetry backend;
- UID/GID 65534; and
- an execution-grant issuer key distinct from both guest- and host-evidence keys.

Consequently, a caller cannot set an `execution_qualified` boolean, reinterpret the current
`fixed_nonexecuting_probe_passed` record, or use the host lifecycle key as a grant issuer. There is
no production code path that can sign a usable grant yet.

## Verification

Six focused tests prove:

- the opaque qualification proof rejects reused evidence/issuer identities and an empty runtime;
- an exact signed grant verifies once and cannot be replayed through the same protected verifier;
- malformed input burns the attempt before parsing and prevents a valid retry;
- clone/context rebinding and key substitution fail closed;
- premature and expired inputs burn before parsing; and
- signature mutation is consumed and rejected.

The macOS-VM crate passes all-target Clippy with warnings denied, and formatting is clean. Extending
the existing package-authority request with candidate-runtime getters did not change its canonical
wire or its explicit false-authority posture.

## Malware handling boundary

Real malware remains restricted to the approved cloud Mac lab workflow. This checkpoint used only
code and inert test values. It did not download, inspect, unpack, transfer, or execute any real
sample, start a VM, or invoke npm or pip.

## Next gate

Build the separate execution-capable runner and runtime image, define its fixed inert qualification
probe and authenticated evidence, then physically qualify those exact bytes on the approved cloud
Mac. Only that verifier may create the opaque qualification proof needed by this grant protocol.
Afterward, integrate one protected grant consumer into the guest agent and run inert npm tarball,
wheel, and nested-sdist scenarios with clone destruction and sync-back structurally absent.
