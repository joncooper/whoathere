# Artifact-Native npm Package Account Checkpoint

Date: 2026-07-10

Status: fixed offline package-account contract, collision checks, privilege rejection, and receipt
binding implemented and fixture-verified; account creation has not yet run against a real mounted
macOS base

Canonical references:

- [Artifact-Native npm Offline Supervisor Provisioning Checkpoint](artifact-native-npm-offline-supervisor-provisioning-checkpoint-2026-07-10.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

## Outcome

The artifact execution identity is no longer only an arbitrary pair of numeric IDs. Provisioning
uses the fixed account and group name `_whoatherepkg`, with default UID/GID `499/499`. An operator
may select different nonzero numeric IDs to avoid a base-specific collision, but cannot change the
account name or its security posture.

While the VM is stopped and its Data volume is mounted, the provisioner scans every local user and
group plist before mutation. A selected UID or GID already assigned to another name fails closed.
The account is then created idempotently through `dscl -f ... localonly` against the offline
`/Local/Target` node with:

- one dedicated primary group;
- home directory `/var/empty`;
- shell `/usr/bin/false`;
- hidden-account marker;
- disabled authentication authority;
- a non-login password marker; and
- explicit membership only in its dedicated group.

After creation, verification reads the actual dslocal plists rather than trusting command success.
It requires exact name, UID, GID, home, shell, hidden marker, disabled authentication, group
membership, protected record ownership/modes, and no direct or nested membership in `admin` or
`wheel`. A mismatch aborts provisioning before supervisor installation completes.

## Identity binding

The fixed package username is present in both:

- the root-owned canonical supervisor configuration whose digest is signed during guest
  authentication; and
- the strict host-side artifact-supervisor provisioning receipt.

The supervisor rejects any configuration whose account name is not `_whoatherepkg`. The Swift
receipt verifier and measured Rust submission generator apply the same requirement. UID/GID remain
bound in the run spec, authentication response, staging receipt, provisioning receipt, and runner
configuration.

The package account still receives no execution authority in this checkpoint. No `setuid`,
`setgid`, process spawn, npm call, consumer workspace, writable cache, or package environment has
been added.

## Verification

The following gates pass:

| Gate | Result |
| --- | --- |
| Package-account plist and privilege self-test | passed |
| Provisioning preflight self-test | passed |
| Measured Rust-frame to Swift-helper self-test | passed |
| Rust Mac backend all targets | 28 passed, 0 failed |
| Swift helper core tests | 31 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 694 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting, shell syntax, production Swift build, and `git diff --check` | passed |

The package-account self-test uses protected temporary plist fixtures. It proves idempotent
acceptance of the exact non-login account, rejection after direct or nested admin membership is
introduced, and rejection when another account already owns the requested UID. It does not claim
that a blank directory is a macOS Directory Service node or substitute a fake database for a
mounted guest.

No VM, guest process, package process, npm process, network, registry, or restricted sample was
used.

## Open gates

The first reachable cloud-Mac run must prove the offline `dscl` creation path against the real
stopped base, re-read the resulting records, and confirm the guest resolves `_whoatherepkg` to the
receipt-bound IDs after boot. The VM must then stop and the clone must be destroyed without ever
launching npm.

Only after that proof may the supervisor add the reviewed supplementary-group clearing and
`setgid`/`setuid` launch boundary. Protected telemetry, descendant cleanup, npm lifecycle execution,
dynamic evidence, verdicts, and malware/benign evaluation gates remain incomplete. Real-malware
execution remains outside this goal's authority.
