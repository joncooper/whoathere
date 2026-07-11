# Artifact-Native npm Offline Supervisor Provisioning Checkpoint

Date: 2026-07-10

Status: offline supervisor provisioning, strict host receipt verification, and measured inert
submission generation implemented and self-tested; no real base was modified and no VM was booted
because the configured cloud Mac endpoint was unreachable

Canonical references:

- [Artifact-Native npm Inert VM Wiring Checkpoint](artifact-native-npm-inert-vm-wiring-checkpoint-2026-07-10.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

## Outcome

The inert VM path now has a reproducible offline provisioning boundary rather than relying on an
unmeasured binary or operator-created key.

The host-only key generator creates one raw Ed25519 seed and matching public key in a new absolute
mode-`0700` directory. It uses exclusive no-follow files, verifies owner/mode/link/device/inode and
exact 32-byte lengths, syncs both files, refuses overwrite, removes partial output, and zeroizes the
seed. It never prints either key.

The admin-only provisioner requires a stopped VM and prebuilt release supervisor/keygen binaries.
It:

1. creates keys under a root-owned temporary directory;
2. ad-hoc signs and verifies a private staged copy of the supervisor;
3. mounts only the stopped base's Data volume;
4. rejects symlinks at every new guest destination;
5. installs the supervisor root-owned mode `0755`;
6. installs the canonical configuration and private seed root-owned mode `0400`;
7. creates the root-owned mode-`0700` staging root;
8. installs a root-owned LaunchDaemon that retries failures but does not restart after a successful
   single session;
9. hashes, but never executes, the trusted Node executable and npm CLI from the mounted base;
10. detaches the VM disk before publishing host metadata; and
11. exports only the public key and a protected canonical receipt into the host bundle.

The temporary directory, including the private seed, is removed on every shell terminal path. The
private seed is never placed in the repository, host bundle, command line, stdout, or receipt.

## Strict provisioning receipt

Artifact runs now require `artifact-supervisor-provisioning.json`; the legacy readiness receipt is
not reused as artifact-supervisor identity. The canonical closed receipt binds:

- base generation;
- supervisor and public-key digests;
- runner-configuration digest;
- fixed VSOCK port `47079`;
- CPU and memory configuration;
- package UID/GID;
- Node and npm versions and exact executable/CLI digests;
- the direct `fclonefileat` implementation identity; and
- package execution and sync-back both false.

The Swift stopped-base verifier parses and byte-canonicalizes this receipt, denies unknown fields,
checks every value against the run-spec backend identity, independently hashes the exported public
key, and requires the fixed clone implementation identity. A receipt with a correct outer file
digest but a substituted supervisor claim fails before clone creation.

## Measured inert submission

The new host-side example generator accepts only absolute state-directory and helper paths. It
opens all fixed base files with `O_NOFOLLOW | O_CLOEXEC`, requires current-user ownership, one link,
protected modes and stable device/inode/length, takes nonblocking shared locks, and hashes each file
incrementally. It strictly parses the supervisor receipt and emits one fresh-challenge binary frame
for the repository-generated inert npm tarball.

The generated run spec binds the exact disk, auxiliary storage, hardware model, machine identifier,
artifact-supervisor receipt, public key, helper, supervisor, runner configuration, Node, npm, clone
implementation, package credentials, and inert artifact bytes. No host path or key is placed in the
frame.

## Verification

The following local gates pass:

| Gate | Result |
| --- | --- |
| Rust Mac backend all targets, including keygen | 28 passed, 0 failed |
| Swift helper core tests | 31 passed, 0 failed |
| Provisioning preflight self-test | passed |
| Measured Rust-frame to Swift-helper self-test | passed |
| Full Rust workspace tests, including compile-fail doc tests | 694 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting, shell syntax, production Swift build, and `git diff --check` | passed |

The cross-language self-test creates protected fake base files on APFS, emits a real measured Rust
submission, and invokes the real Swift `artifact-run --execute` parser. Deliberately invalid
Virtualization metadata forces failure at the VM-configuration boundary. The helper reports package
execution false and proves the APFS clone was removed. No VM starts.

All artifacts were inert and generated locally. No guest binary was executed on the host, no VM or
package process ran, no network or registry was used, and no restricted sample was accessed.

## Live-run boundary

The local workspace host has no VM state, and the configured remote Mac aliases were unreachable
during this checkpoint. No provider address, key, or machine identity is recorded here. The live
gate therefore remains open rather than being replaced with a fixture claim.

When the cloud Mac is reachable, the next authorized inert-only steps are:

1. build the release helper, supervisor, key generator, and measured submission generator there;
2. run the provisioning preflight against the stopped validation base;
3. confirm the selected UID/GID denotes a dedicated non-admin package account;
4. run the admin-only offline provisioner and retain only the public receipt material;
5. run one measured inert frame through `artifact-run --execute`;
6. require `staged_no_execution`, authenticated receipt, VM stop, channel EOF, and clone absence;
7. rehash the stopped base and confirm it was not launched writable; and
8. inject bounded connection/auth/body/receipt/stop failures before enabling npm.

Real-malware execution remains outside this goal's authority. npm execution, protected telemetry,
dynamic verdicts, wheel/sdist execution, benign-friction gates, and corpus gates remain incomplete.
