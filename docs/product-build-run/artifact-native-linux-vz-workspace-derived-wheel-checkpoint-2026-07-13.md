# Artifact-Native Linux VZ Workspace and Derived-Wheel Checkpoint

Date: 2026-07-13

Status: fixed tmpfs-workspace construction, direct derived-wheel normalization/sealing, and
fixed-console-target process planning are implemented and cross-compiled; they are not yet wired
into the protected guest agent, physically exercised, sensor-correlated, or signed

## Outcome

The protected root path now has source-level primitives for creating the exact writable filesystem
shape required by npm and Python package scenarios and for converting an sdist build output into
one measured, immutable wheel input. The later derived-wheel pip action can receive an opaque
validator-created binding containing both the fixed path and the exact wheel digest. The launch
contract adds that wheel as a measured input rather than treating a discovered filename as
authority.

The console-entry-point probe no longer depends on executing a pip-generated wrapper. It now uses
the root-sealed virtual-environment Python copy plus one fixed Python program. The validated module
and callable are separate argv data, the fixed program recreates the console-call convention, and
--help remains the only argument profile. This avoids both trusting wrapper bytes and Linux
script-through-execveat interpreter edge cases while still importing and invoking the package
target that the normalized wheel metadata declared.

No package, VM, helper, or sample was executed while implementing or testing this checkpoint.

## Fresh workspace boundary

MaterializedLinuxVzPackageWorkspaceV1 has one production constructor. On Linux it:

- requires the already validated root-supervisor materialization policy;
- opens and validates the fixed root-owned /run parent without following a symlink;
- fails if /run/whoathere already exists;
- mounts a fresh 1 GiB tmpfs with a fixed 131,072-inode limit, nodev, nosuid, and executable
  package files;
- proves the mounted filesystem is tmpfs and the root is root-owned mode 0755;
- creates only home, tmp, cache/npm, work/npm, and derived;
- transfers those writable directories to package UID/GID 65534 at mode 0700; and
- retains every directory descriptor and binds device, inode, owner, group, and mode in canonical
  observation bytes.

The workspace verifier requires all fixed top-level names and rejects any unknown top-level name.
It permits only the separately retained root-created input, source, and closure materializations.
It reopens every fixed directory without following a symlink and requires the same descriptor
identity. Contents beneath package-writable directories may change during a scenario, but the
directory boundary itself cannot be silently deleted and replaced.

The production cleanup path closes retained workspace descriptors, unmounts the tmpfs, removes the
fixed mountpoint, and fails closed if verification or cleanup does not complete. The workspace
observation grants no execution authority and carries no sync-back field capable of being enabled.

## Derived-wheel parser without invented provenance

The artifact normalizer now exposes normalize_derived_wheel. It takes only an exact safe wheel
basename, exact bytes, and the existing normalization limits. It deliberately does not manufacture
a registry, custody, local-file, or inert-fixture acquisition envelope for build output.

The parser applies the same bounded ZIP and wheel rules as acquired wheels:

- one .dist-info directory;
- required and bounded METADATA, WHEEL, and RECORD;
- matching distribution/version identities across filename, .dist-info, and metadata;
- canonical wheel tags and build tag;
- complete RECORD coverage with exact hashes and lengths;
- parsed entry points, .pth files, scripts, import roots, native tags, and dependencies; and
- a complete canonical artifact manifest bound to the exact derived-wheel digest.

This is non-executing parsing. It does not extract the wheel or invoke Python/pip.

## Exactly-one output and root sealing

validate_single_linux_vz_package_derived_wheel_v1 is available only for a process plan containing
exactly one ValidateSingleDerivedWheel action. It:

1. verifies the retained workspace and package-owned derived directory;
2. enumerates the directory through its descriptor and requires exactly one entry;
3. requires one safe ASCII canonical .whl basename;
4. opens the leaf without following a symlink;
5. requires a regular, single-link, bounded, package-owned file that is not group/other writable;
6. reads and hashes the exact file and normalizes it with the derived-wheel parser;
7. requires complete normalization, no issues, and a valid manifest digest;
8. changes the exact file to supervisor ownership and mode 0444;
9. changes the retained derived directory to supervisor ownership and mode 0555; and
10. reopens and rehashes the exact name, requiring the same device and inode.

The validator retains the run-root, directory, and wheel file descriptors. Its prelaunch and
postrun checks require the sealed directory to contain only that exact name and require the exact
file identity, length, digest, ownership, and mode.

The opaque dynamic binding now contains both the fixed
/run/whoathere/derived/<validated-basename> path and its SHA-256. Only the derived-wheel validator
can construct that production binding. When the pip-install action consumes it, the launch
contract appends the wheel as a DerivedWheel measured input. Missing, partial, unexpected,
duplicated, or malformed bindings fail closed.

## Console target correction

The process plan still binds the normalized console command name, module, callable, and the
SHA-256 of module:callable. The internal action is now a semantic
ValidateConsoleEntryPointTarget, not a request to discover or execute a generated script.

The subsequent process action is fixed to:

- the copied virtual-environment Python executable already bound to the qualified runtime digest;
- isolated Python mode;
- one immutable root-owned code string;
- command name, module, and callable as validated argv data; and
- one literal --help argument.

The fixed code imports the module, resolves the callable by attribute traversal, restores the
declared command name as argv[0], sets the argument shape, and invokes it. Package initialization
and callable behavior therefore still run in the
contained scenario, but package-controlled wrapper bytes never select the executable or program.

The process-plan and launch-contract wire identities changed. No prior runner or runtime-image
identity may be reused.

## Verification

Verification used deterministic inert fixtures and compilation only:

- the full repository test suite passed, including doc tests and loopback-only fake-provider tests;
- six artifact-normalization integration tests passed, including a direct derived-wheel case and
  a filename/metadata mismatch rejection;
- whoathere-macos-vm: 136 native library tests passed;
- the workspace tests prove exact initial topology, descriptor-bound ownership/modes, unexpected
  top-level rejection, cleanup, and platform closure on macOS;
- the derived-wheel tests prove exactly-one enforcement, full normalization, file/directory
  sealing, stable observation hashing, opaque path-plus-digest binding, launch-contract measured
  input inclusion, and zero/multiple/invalid-output rejection;
- the console-plan test proves the module and callable are data to the fixed virtual-environment
  Python program;
- native warnings-denied Clippy passed for all whoathere-artifact and whoathere-macos-vm targets;
  and
- Linux/aarch64-musl warnings-denied Clippy passed for all whoathere-macos-vm targets, including
  the tmpfs mount and descriptor paths.

The Linux workspace constructor was cross-compiled only. No local mount, package installation,
sdist build, or process launch occurred.

## Malware handling boundary

Real malware runs only on the approved cloud Mac under the restricted lab workflow, inside a fresh
disposable Linux VZ clone. This checkpoint did not access the cloud Mac and did not download,
transfer, inspect, unpack, or execute a real sample. It did not run a package locally, start a VM,
use Docker for detonation, enable sync-back, contact live C2, or fetch a second stage.

## Claim boundary and next gate

This checkpoint removes two sources of open-ended execution input: caller/discovery-selected build
output paths and package-generated console wrapper programs. It does not create authoritative
dynamic evidence and does not improve the current 7/11 malicious-package detection result.

The next gate is the protected root sequencer. It must:

1. consume one execution attempt and create this workspace;
2. execute internal materialization actions and fixed process actions strictly in plan order;
3. start the qualified protected process/file/network sensors before releasing each action cgroup;
4. bind workspace, artifact, sdist, closure, derived-wheel, launch, supervisor, sensor, and teardown
   observations into one failure-closed response;
5. reject any sensor gap, lineage disagreement, truncation, leftover descendant, cleanup failure,
   or unconsumed/unexpected action;
6. sign the guest response and bind it to independently observed host VM lifecycle evidence; and
7. rebuild and independently qualify the exact Linux/aarch64 runner and runtime image.

Only after that gate should inert npm, exact wheel, and nested-sdist cases run in fresh Linux VZ
clones on the approved cloud Mac. Benign controls and restricted real-malware regression remain
later, separately approved gates.
