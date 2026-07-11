# Artifact-Native npm Inert VM Wiring Checkpoint

Date: 2026-07-10

Status: single-use macOS guest-supervisor entry point and Swift zero-NIC disposable-VM lifecycle
wired and locally verified without booting a VM; no base-image provisioning, live VSOCK proof,
package process, npm execution, protected telemetry, detection, or admission claim

Canonical references:

- [Artifact-Native npm Non-Executing Guest Session Checkpoint](artifact-native-npm-nonexecuting-guest-session-checkpoint-2026-07-10.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

## Outcome

The first artifact-native npm VM path is now connected in code from the helper's binary stdin to a
separate single-use guest supervisor. It still stops before npm or any artifact-controlled process.

The Rust guest supervisor session:

1. accepts only a typed authentication challenge;
2. signs the measured claims with the provisioned Ed25519 identity;
3. receives one exact raw artifact frame after authentication;
4. rejects any run-spec or execution binding that differs from the challenge;
5. also requires the staged run spec to match the measured supervisor, runner configuration,
   public key, package UID, and package GID;
6. performs the protected first rehash;
7. constructs the signed non-executing staging receipt;
8. explicitly removes the staged file and scenario directory before sending the receipt; and
9. returns a result whose package-execution field is always false.

The production-shaped `whoathere-artifact-supervisor` binary is macOS-only and accepts no argv. It
requires effective UID 0 and fixed paths for a canonical mode-`0400` configuration, mode-`0400`
32-byte signing seed, and protected staging root. It checks opened-file and path device/inode
identity, root ownership, one-link posture, length bounds, modes, and pre/post-read stability for
its executable, configuration, and seed. Both in-memory copies of the raw seed are zeroized.

The binary connects only to host CID 2 on the new artifact VSOCK port `47079`. Connection setup is
nonblocking and deadline-bound. All subsequent reads and writes share one absolute 90-second
deadline, so byte trickling cannot extend the session. The binary handles one connection, closes
its write side after the final receipt, and exits. It has no listener loop, package command, shell,
network fallback, file-return operation, sync-back operation, or verdict.

## Swift disposable-VM path

The helper's `artifact-run --execute` path now:

- parses and validates only the bounded submission prelude before touching the VM lifecycle;
- locks and remeasures the exact stopped base, helper, guest public key, and metadata;
- creates one APFS clone with no copy fallback;
- builds the separate configuration whose `networkDevices` list is empty;
- registers a one-connection listener only on artifact port `47079` before VM start;
- authenticates the guest before forwarding any artifact byte;
- requires the signed staging receipt and final EOF;
- removes the listener and requests a bounded guest stop, escalating to `VZVirtualMachine.stop`;
- authorizes clone removal only after both VM stop and guest-session termination are proven; and
- emits a non-admission `staged_no_execution` observation with package execution and sync-back
  explicitly false.

If VM stop is unproven or the connection worker has not terminated, the helper retains the clone
instead of racing deletion against a live VM or thread. That residue is an explicit terminal error,
not a clean result. Every terminal path created after clone allocation handles the clone explicitly
before the helper's process-exiting JSON emitter is called.

## Fault-oriented verification

Focused tests and local smoke checks cover:

- a complete guest-side challenge, signed response, exact-byte stage, rehash, explicit cleanup,
  signed receipt, and no-execution result;
- rejection of a challenge/header execution-binding substitution after staging, with no receipt and
  an empty staging root;
- canonical closed guest configuration and nonzero package credentials;
- a real Ed25519 key derived from the configured seed shape;
- host-side rejection of execution-enabled or rebound receipts;
- typed-frame timeout, wrong-order, truncation, and final-EOF failures;
- clone-cleanup authorization only when VM stop and guest-session termination are both proven;
- fail-closed helper behavior when `--execute` is absent or stdin is truncated; and
- the existing APFS clone failure/retry, measured-base mutation, and no-NIC configuration tests.

The closeout validation table is:

| Gate | Result |
| --- | --- |
| Rust Mac backend library, supervisor-binary, integration, and example targets | 27 passed, 0 failed |
| Swift helper core tests | 31 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 693 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting, production Swift build, and `git diff --check` | passed |

All artifacts were repository-generated inert fixtures. No cloud Mac, VM boot, production key,
package process, npm process, registry, network, or restricted sample was used.

## Open gates

This checkpoint proves compiled wiring and local protocol/lifecycle policy, not a booted guest. The
next slice must:

1. add an offline, root-owned provisioning path for the supervisor binary, canonical config,
   private seed, public-key export, staging root, and LaunchDaemon;
2. produce a new artifact-supervisor provisioning receipt and bind its exact digest into the base
   identity;
3. verify the selected package UID/GID is a dedicated non-admin guest account before any execution
   work begins;
4. build a production-shaped inert submission from the measured stopped base;
5. run one real no-NIC VM scenario on the authorized Mac and prove authentication, exact staging,
   stop, connection termination, and clone absence;
6. inject boot, connection, authentication, body, receipt, stop, and cleanup failures against the
   live lifecycle; and
7. remeasure the base after the campaign and prove it was never booted as the writable scenario
   disk.

Only after those gates pass should the typed npm package-user launch boundary be added. Protected
process/file/network telemetry and package-specific verdicts remain later blocking work. The
restricted eleven-sample corpus remains closed pending its separate lab approval.
