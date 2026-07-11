# Artifact-Native sdist Supervisor Provisioning Checkpoint

Date: 2026-07-11

Status: a fail-closed stopped-base provisioner and canonical sdist supervisor receipt renderer now
exist and pass non-mutating preflight tests; no VM disk has been modified and live VZ qualification
remains open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Helper VZ Route Checkpoint](artifact-native-sdist-helper-vz-route-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Supervisor Identity Checkpoint](artifact-native-sdist-supervisor-identity-checkpoint-2026-07-11.md)

## Outcome

`provision-sdist-supervisor.sh` can now preflight or provision a stopped macOS VM base for the
dedicated sdist guest path. Its preflight is non-mutating and requires:

- an absolute, owner-controlled state directory and bundle;
- a regular, single-link, owner-controlled base disk;
- separate executable sdist supervisor and keygen release binaries;
- safe binary ownership and modes; and
- no active VM runtime PID.

Preflight reports the fixed package account, VSOCK port `47081`, and all disabled capabilities. It
does not attach the disk, generate keys, or change the base.

## Provisioning behavior

The privileged path refuses to run unless the preflight passes and the state owner matches the
invoking sudo user. It then:

1. creates a private temporary build root;
2. generates a fresh sdist-only Ed25519 seed/public-key pair;
3. stages, ad-hoc signs, and strictly verifies the release sdist supervisor;
4. creates the closed root-owned sdist supervisor config;
5. constructs and validates the dedicated launch daemon;
6. attaches the stopped base disk read-write with owners enabled;
7. finds exactly one fixed Python executable, pip CLI, and pip metadata record;
8. measures Python, pip, supervisor, config, key, clone implementation, and sdist protocol;
9. provisions the fixed unprivileged package account;
10. rejects symlink destinations before installing supervisor, config, seed, launch daemon, and
    private sdist staging root;
11. syncs and detaches the disk; and
12. atomically installs the public key and canonical provisioning receipt into the host bundle.

The cleanup trap detaches an attached disk and removes the private build root on success, error, or
signal.

## Closed receipt

`sdist-supervisor-receipt-lib.sh` renders the exact canonical JSON schema consumed by the Swift
measured-base verifier. It binds:

- base generation;
- clone implementation;
- CPU and memory;
- guest authentication public key;
- sdist guest protocol and supervisor;
- package UID, GID, and username;
- Python executable and version;
- pip CLI and version;
- runner configuration; and
- VSOCK port `47081`.

It always emits these immutable safety values:

- `package_execution_enabled=false`;
- `sync_back_enabled=false`;
- `build_closure_materialization_enabled=false`; and
- `public_resolution_enabled=false`.

There is no provisioner option that can enable them.

## Verification

The inert provisioning self-test passed. It proves:

- safe state, bundle, disk, and stub binaries pass preflight;
- all four disabled capabilities and port `47081` are reported;
- the receipt renderer produces the exact expected canonical JSON;
- a group/world-writable bundle is rejected with the exact reason code; and
- an active runtime PID is rejected before provisioning.

Both scripts pass `sh -n`. No privileged path, disk attachment, key generation, code signing, VM,
package manager, build backend, network, restricted sample, or malware was used.

## Claim boundary and next gate

This checkpoint proves the provisioner logic and non-mutating preflight contract. It does not prove
that the current local or cloud Mac base is present, independently identified, stopped, or ready to
be changed. It also does not prove an installed launch daemon or live VSOCK session.

Before any disk mutation, the target Mac identity and state directory must be independently
confirmed. Then the provisioner can run against the stopped inert base, followed by receipt
measurement and one inert staging-only VZ qualification. Restricted samples remain out of scope.
