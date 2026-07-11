# Artifact-Native npm Disposable Lifecycle Primitives Checkpoint

Date: 2026-07-10

Status: complete boot-input measurement contract, stopped-base verifier, APFS clone/cleanup
primitives, and separate zero-NIC VZ configuration builder implemented; no authenticated execution
authority, VM boot, guest channel, package execution, telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Swift Transport Parser Checkpoint](artifact-native-npm-swift-transport-parser-checkpoint-2026-07-10.md)

## Outcome

The artifact Mac run spec now binds every host-side input needed to construct the initial VM
configuration. In addition to the stopped-base disk, auxiliary storage, provisioning receipt,
helper, guest supervisor, runner, Node, npm, clone implementation, and guest protocol identities,
the backend identity now carries the exact hardware-model and machine-identifier digests and the
CPU and memory settings. The strict Rust and Swift decoders require these fields, include them in
the canonical run-spec and execution-binding identities, and enforce bounded CPU and memory values.

The Swift core can verify and lock that complete base, produce one proven APFS clone per call, and
construct the separate artifact-only VZ configuration. None of these primitives is connected to
the `artifact-run` command. The command continues to parse the exact transport and return exit 78
with VM and package execution disabled because authenticated challenge authority is still absent.

## Stopped measured base

`verifyAndLockArtifactRunBase` uses only fixed names under the selected state directory. It requires
the state and bundle directories to be real, same-user-owned directories with no group/other write
permission. A present runtime PID record is parsed fail-closed; a live process, inaccessible PID,
malformed record, permission drift, or PID reuse blocks the artifact base.

The verifier opens the disk, auxiliary storage, hardware model, machine identifier,
post-provisioning receipt, and current helper with `O_NOFOLLOW` and `O_CLOEXEC`. Every object must be
a nonempty regular file, have one link, be owned by the helper UID, and be non-writable by group and
others. The verifier takes a nonblocking exclusive advisory lock on each open object, hashes through
the held descriptor, requires the exact run-spec digest, and retains the descriptors and locks for
the lifetime of the base and all child clones. Hardware-model and machine-identifier data are
captured only within 1 MiB limits; the receipt is capped at 4 MiB and the helper at 64 MiB.

This protects against symlink and path substitution and binds the selected helper executable.
Production wiring must pass the current signed executable identity. Advisory locks do not constrain
a hostile same-UID process by themselves. The clone is
therefore rehashed against the expected base digest before it can be used, while protected ownership
and the held descriptors preserve the selected source identity. Full pre/post-campaign base hashing
remains required for the first cloud-Mac qualification.

## APFS clone and cleanup

Each clone uses a cryptographically random 128-bit identifier and a mode-`0700` directory beneath a
dedicated `artifact-runs` root. The implementation calls `fclonefileat` directly from the already
measured disk and auxiliary-storage descriptors. `ENOTSUP` and cross-filesystem failures are typed
as unsupported; there is no byte-copy, persistent-disk, legacy-bundle, or partial-clone fallback.

Before returning, the helper reopens both destinations without following links and requires:

- a regular, single-link, same-user-owned, protected file;
- the exact expected length and SHA-256;
- an inode identity distinct from the source; and
- unchanged source descriptor identities after both clones are complete.

The clone object owns open directory descriptors and retains the locked base. Cleanup removes only
the owned clone members, removes the unique run directory, and verifies absence through the open
parent directory. A failed removal keeps the descriptors and path available for an explicit retry;
it is not relabeled as successful cleanup. Deinitialization makes a final best-effort retry, but a
caller must preserve and report an explicit cleanup failure.

APFS clone deletion here means verified namespace removal. It is not a secure-erasure claim.

## Separate zero-NIC VZ configuration

`buildArtifactScenarioConfiguration` is independent of the legacy persistent-project builder. It
loads only the measured hardware model and machine identifier, attaches only the writable cloned
disk and cloned auxiliary storage, and uses the bound CPU and memory values. It explicitly sets:

```swift
configuration.networkDevices = []
```

The artifact contract has one VSOCK device, one writable storage device, no guest-tools attachment,
and no NAT fallback. The builder validates the final `VZVirtualMachineConfiguration` before it can
be returned. Unit tests exercise the pure configuration contract; final validation with authentic
VZ metadata belongs to the inert local and cloud-Mac campaign.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Swift helper protocol, lifecycle, and existing core tests | 20 passed, 0 failed |
| Rust Mac backend tests with all targets | 17 passed, 0 failed |
| Rust-to-Swift inert frame interoperability after boot-input expansion | parsed and blocked as designed, exit 78 |
| Full Rust workspace tests, including compile-fail doc tests | 683 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting and `git diff --check` | passed |
| Production Swift helper build | passed |

The lifecycle tests run on the local Mac filesystem and cover two distinct APFS clones from one
locked base, exact disk and auxiliary-storage bytes and digests, source/destination inode
separation, unique run identities, zero-NIC configuration facts, explicit cleanup, verified path
absence, cleanup fault and retry, base digest mismatch, symlink rejection, and active-runtime
rejection.

All inputs were tiny repository-generated inert fixtures. No real model, cloud Mac, VM boot, guest
code, npm process, network, package registry, or restricted sample was used.

## Open gates

Before these primitives may be called by `artifact-run`, the helper needs a protected authority
channel that supplies and atomically consumes the pre-issued expected execution binding. The next
steps are then:

- validate the real signed helper and post-provisioned base against the expanded measurement shape;
- build and validate the authentic zero-NIC VZ configuration without starting it;
- add the new bounded artifact VSOCK framing and session identity;
- implement bounded VM start/stop and unconditional channel/clone teardown without npm;
- return authenticated transport and lifecycle observations only; and
- qualify repeated inert scenarios locally and on the approved cloud Mac.

The root guest supervisor, package UID transition, exact artifact staging, npm lifecycle execution,
dynamic sensors, and verdict aggregation remain later landings. Real-malware execution remains
outside this goal's authorization.
