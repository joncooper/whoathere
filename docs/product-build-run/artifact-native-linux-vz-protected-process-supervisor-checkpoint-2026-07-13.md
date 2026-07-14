# Artifact-Native Linux VZ Protected Process Supervisor Checkpoint

Date: 2026-07-13

Status: the fixed process plan now derives a closed launch contract, root-sealed executable
measurement, and a cgroup-v2 process-supervision primitive; it is cross-compiled but not yet wired
into the protected guest agent, physically exercised, sensor-correlated, or signed

## Outcome

The execution path now has a source-level boundary between a semantic package action and Linux
`execveat`. For each process action, the new launch contract fixes the executable class, exact
`argv`, cleared-and-replaced environment, current directory, measured auxiliary inputs, scenario
limits, cgroup policy, credential policy, bounded output policy, and complete-descendant teardown
policy. It accepts no caller executable, argument, environment variable, working directory, or
resource limit.

The Linux implementation immediately remeasures the exact executable and measured inputs, retains
their file descriptors, places a blocked child in its new cgroup before releasing it, drops the
child to UID/GID 65534 with no supplementary groups and no-new-privileges, and executes the retained
file descriptor. The root supervisor remains outside the package cgroup as a subreaper. Natural
exit, timeout, background descendants, session changes, and double-fork descendants therefore all
converge on the cgroup rather than a process-group-only cleanup assumption.

This checkpoint does not make the existing unprivileged validation runner execution-capable. The
new primitives are library code for a separate future root supervisor. No package, helper, VM, or
sample was executed while implementing or testing them.

## Closed launch contract

`LinuxVzPackageProcessLaunchContractV1` is derived only from one indexed `Process` action in the
canonical process plan. It binds:

- the process-plan digest, action index, and exact stage name;
- the executable class, absolute path, and expected SHA-256;
- `argv[0]` plus every fixed post-`argv[0]` argument;
- one exact environment map after a mandatory environment clear;
- the fixed `/run/whoathere` current directory;
- each measured npm or pip input path and digest;
- scenario-wide wall time, stdout/stderr caps, process and file-descriptor limits;
- cgroup memory, swap, PID, CPU, and OOM-group policy;
- CPU, core, file-size, address-space, open-file, and process rlimits;
- a 250 ms TERM grace and five-second forced-teardown deadline; and
- fixed UID/GID, no-supplementary-group, no-new-privileges, subreaper, cgroup-v2, no-public-route,
  and no-sync policies.

The contract is canonical JSON with its own digest, but deliberately reports
`launch_authority_present=false` and `package_execution=false`. It cannot authorize execution by
itself. An opaque scenario authority must also be derived from the structurally validated request
that represents the already burned one-use execution grant. It binds the execution-grant digest,
attempt binding, and process-plan digest. Each process action is burned before privilege checks,
measurement, cgroup creation, or fork; the same action cannot be retried through the same authority.

The process plan now directly includes the validated scenario limits and exposes its exact
execution-request digest for this binding. Its wire and digest therefore changed again; no prior
runner or runtime-image identity is reused.

## Dynamic-path gate remains closed

Literal arguments are copied only from the closed process plan. A derived-wheel argument requires
an opaque validated derived-wheel binding and must be one ASCII `.whl` basename directly under
`/run/whoathere/derived`. A derived console entry point requires both the exact plan path and a
validator-supplied executable digest.

There is intentionally no production constructor for either dynamic binding in this checkpoint.
Until the single-derived-wheel and console-wrapper validators construct those opaque values, the
later sdist-install and console-entry-point actions fail closed rather than accepting a discovered
path.

## Exact executable custody

The measurement layer opens all paths beneath an already opened filesystem-root descriptor using
Linux `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and
`RESOLVE_NO_MAGICLINKS`. The leaf must be one regular, single-link file with safe ownership and
mode, a bounded size, and the contract-bound SHA-256.

Pinned Node, Python, npm, and pip inputs must remain root-owned and non-writable by group or other.
Package-generated virtual-environment Python copies and validated console wrappers initially must
be package-owned, single-link, non-group/other-writable executables with the expected digest. The
root supervisor then changes them to root ownership and mode `0555`, syncs them, reopens them
through the same no-symlink path policy, and rehashes them. This removes package write authority
before execution and avoids a hash-then-rewrite race.

The exact executable file descriptor is retained through immediate-preexec verification and passed
to Linux `execveat` with `AT_EMPTY_PATH`. Measured npm/pip file descriptors and the exact current
directory descriptor are also retained. Pre-exec and post-run verification reopen every name,
rehash every file, and require the same device, inode, owner, group, mode, link count, length, and
digest as the retained descriptor. Package-generated executables therefore cannot be substituted
by changing a parent symlink or path after validation.

## Cgroup and child boundary

The process supervisor requires real/effective root UID and GID, disables supervisor dumpability,
and enables `PR_SET_CHILD_SUBREAPER`. It opens and proves the cgroup-v2 filesystem, creates one fixed
action cgroup, requires a domain cgroup, applies the contract limits, and proves it initially empty.

The child starts with no package code running and blocks on a root-controlled pipe. The parent adds
that exact PID to `cgroup.procs`, rereads membership, and only then sends the release byte. Before
`execveat`, the child:

1. binds its death to the root parent with `PR_SET_PDEATHSIG(SIGKILL)`;
2. creates a new session;
3. changes directory through the retained descriptor;
4. applies all fixed rlimits;
5. removes supplementary groups and sets real/effective/saved GID and UID to 65534;
6. clears ambient capabilities, disables dumpability, and sets no-new-privileges; and
7. installs `/dev/null` stdin plus bounded stdout/stderr pipes.

The root supervisor drains output without blocking the child. It hashes the complete observed
stream while retaining only the configured prefix and recording truncation. The scenario clock is
created once from the whole process plan, so sequential actions share one monotonic wall deadline
rather than each receiving a fresh full timeout.

On deadline or a leader exit with a populated cgroup, the supervisor sends one TERM to each current
cgroup process. After the fixed grace it uses `cgroup.kill`, reaps adopted descendants, requires
`populated 0`, drains both output pipes to EOF, and removes the cgroup. Its error-path destructor
also issues `cgroup.kill` and waits boundedly for empty membership, so an evidence or I/O failure
does not intentionally bypass teardown. Successful supervisor evidence binds the grant and attempt,
launch contract, pre-exec and post-run measurement digests, leader terminal status, monotonic
deadline state, TERM/KILL use, background-descendant state, reap count, full-stream output digests,
bounded captures, and proven cgroup removal.

## Evidence boundary

The supervisor evidence is canonical and digest-bound, but it is not yet authoritative dynamic
evidence. It has not yet been correlated with the protected BPF/fanotify/network sensors or placed
inside the existing guest-signed and host-signed receipt flow. It must not be treated as proof that
a lifecycle/build/import trigger ran or that a behavior was detected.

The future protected guest agent must fail the scenario if the independent sensor is missing,
suppressed, truncated, unhealthy, or disagrees with supervisor lineage and cgroup identity. Only
the combined signed evidence may reach the verdict engine.

## Verification

Verification used only source compilation and deterministic inert unit tests:

- the full repository test suite passed, including doc tests and loopback-only fake-provider tests;
- `whoathere-macos-vm`: 131 native library tests passed;
- native warnings-denied Clippy passed for all crate targets;
- Linux/aarch64-musl warnings-denied Clippy passed for all crate targets, including the supervisor;
- the new launch-contract tests prove exact npm argv/environment/resource binding, distinct CI
  profiles, internal-action rejection, and rejection of unexpected dynamic paths;
- the new attempt-authority test proves a process action burns once and cannot be retried;
- formatting and `git diff --check` passed.

The Linux process path was cross-compiled only. macOS cannot physically exercise cgroup v2 or the
Linux `openat2`/`execveat` boundary, and this checkpoint did not use a Linux VM merely to turn a
compile result into a runtime claim. Physical qualification remains an explicit next gate.

## Malware handling boundary

Real malware runs only on the approved cloud Mac under the restricted lab workflow, inside a fresh
disposable Linux VZ clone. This checkpoint did not access the cloud Mac and did not download,
transfer, inspect, unpack, or execute a real sample. It did not run a package locally, start a VM,
use Docker for detonation, enable sync-back, contact live C2, or fetch a second stage.

## Claim boundary and next gate

This checkpoint closes the source-level process-launch and cgroup-teardown primitive. It does not
yet provide an end-to-end execution-capable runtime and does not improve the current 7/11
malicious-package detection result.

Before the first physical inert package case, the protected root agent still must:

1. construct the fixed writable work, cache, home, tmp, and derived namespaces;
2. sequence artifact, sdist, closure, and process actions under one consumed attempt authority;
3. implement single-derived-wheel, metadata, and console-wrapper validation and create the opaque
   dynamic bindings;
4. start and bind the qualified protected process/file/network sensors to each action cgroup;
5. combine materialization, supervisor, protected-sensor, and teardown observations in a strict
   guest-signed response with host lifecycle evidence;
6. rebuild and independently qualify the exact Linux/aarch64 runner and runtime image; and
7. run only inert npm, wheel, and nested-sdist trigger fixtures in fresh Linux VZ clones on the
   approved cloud Mac.

Benign controls and restricted real-malware regression remain later, separately approved gates.
