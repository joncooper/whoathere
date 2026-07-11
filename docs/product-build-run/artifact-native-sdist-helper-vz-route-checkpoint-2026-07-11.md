# Artifact-Native sdist Helper VZ Route Checkpoint

Date: 2026-07-11

Status: the packaged helper now has a measured sdist base, APFS clone lifecycle, zero-NIC VZ
configuration, and sdist-only authority-first production route; stopped-base provisioning and an
inert live VZ qualification run remain open, and package execution/build-closure materialization
remain disabled

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Supervisor Identity Checkpoint](artifact-native-sdist-supervisor-identity-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Swift Authorized Guest Checkpoint](artifact-native-sdist-swift-authorized-guest-checkpoint-2026-07-11.md)

## Outcome

The helper accepts a distinct `sdist-run` invocation with only:

- optional state directory;
- required single-use authority id;
- required authority-record SHA-256;
- explicit `--execute`; and
- optional JSON output.

It rejects legacy package-manager, project-payload, arbitrary argv, and sync-back flags. Without
`--execute`, the release helper exits blocked before reading stdin, with VM execution, package
execution, sync-back, and build-closure materialization all reported false.

With explicit execution intent, the route calls `beginAndAuthorizeSdistRunSubmission` on stdin.
That function validates only the bounded prefix/header and burns the exact authority before the
route can verify a base, create a clone, install a VSOCK listener, or start VZ.

## Measured stopped base

The new sdist base layout requires fixed paths for:

- base disk and auxiliary storage;
- hardware model and machine identifier;
- `sdist-supervisor-public-key.bin`;
- `sdist-supervisor-provisioning.json`; and
- stopped-runtime state.

The closed provisioning receipt binds the base generation, sdist supervisor, Ed25519 public key,
runner config, Python executable/version, pip CLI/version, clone implementation, sdist guest
protocol, CPU, memory, package account, and VSOCK port `47081`. It also requires these capabilities
to be false:

- package execution;
- sync-back;
- build-closure materialization; and
- public dependency resolution.

The helper opens every base object with `O_NOFOLLOW`, verifies owner/mode/link/size and exact digest,
holds locks and file descriptors across the lifecycle, and rejects an active base runtime.

## Disposable VZ contract

Each run creates distinct APFS clones of the measured disk and auxiliary storage. There is no copy
fallback. Clone digest, size, inode separation, and unchanged source identity are verified before
use.

The VZ contract has:

- zero network devices;
- exactly one VSOCK device on port `47081`;
- one writable cloned storage device;
- no guest-tools attachment;
- measured Mac hardware and machine identity; and
- CPU and memory fixed by the bound backend identity.

The guest listener receives only `AuthorizedSdistRunSubmission`; it cannot reconstruct authority
from CLI strings or a raw prelude.

## Stop and cleanup policy

After a start attempt, the route removes the listener and requests VM stop. Clone deletion is
authorized only when both VM stop and guest-session termination are proven. An unproven stop or
unterminated guest session retains the clone and emits a domain-specific error instead of claiming
cleanup. All result paths keep package execution, sync-back, and closure materialization false.

## Verification

Verification used generated inert files only:

- 22 focused sdist Swift tests passed;
- the complete packaged-helper suite passed 75 tests;
- the release helper built successfully;
- measured-base tests rejected wrong receipts and active runtime state;
- two distinct APFS clones were created, measured, and removed;
- the VZ contract reported zero NICs and sdist port `47081`;
- CLI tests rejected missing authority fields and all sync/project/package-manager flags;
- cleanup-policy tests require both VM stop and guest termination; and
- the release CLI dry run exited 78 with every execution/sync/materialization capability false.

No VM was started. No disk image was modified. No package manager, build backend, network,
restricted sample, or malware was used.

## Claim boundary and next gate

This checkpoint proves the compiled route and inert lifecycle components. It does not prove that a
real stopped base has been provisioned with the measured sdist supervisor, runtime, config, key,
launch daemon, and receipt. It also does not prove live VZ connection, guest cleanup, cancellation,
or post-stop clone deletion.

The next slice is to add a fail-closed sdist supervisor provisioner and preflight self-test. After
the base is provisioned and its identity is independently confirmed, one inert live staging run can
qualify the route. That run must still stop before build-closure materialization or package code.
