# Artifact-Native Linux VZ Protected Sequencer Checkpoint

Date: 2026-07-13

Status: the sensor-mandatory supervisor contract, strict sensor-correlation decoder, console-target
validator, and root execution sequencer are implemented and cross-compiled; no production sensor
channel implements the sealed observer yet, the transcript is unsigned and verdict-ineligible,
and no package process can currently be released through this path

## Outcome

The package process supervisor no longer exposes a sensorless production path. A protected
observer is now mandatory, and the observer trait is sealed to this crate. Before the unprivileged
child can leave its blocked pre-exec state, the observer must be armed against the exact cgroup and
must acknowledge the exact leader PID after cgroup attachment. Completion requires canonical,
fresh, cgroup-bound process/file/network correlation plus detailed payloads whose hashes match the
correlation record.

A root sequencer now composes the previously separate workspace, exact artifact, sdist source,
build closure, derived-wheel, launch-contract, measurement, supervisor, and cleanup primitives. It
executes only the fixed action order in the process plan. It returns a bounded canonical transcript
only after final rehashes and explicit tmpfs cleanup succeed.

The transcript is intentionally marked authenticated=false and verdict_eligible=false. There is
not yet a production observer implementation or signing layer, so this checkpoint does not make
package execution available and cannot create dynamic detection evidence.

No package, VM, helper, cloud host, or malware sample was executed while implementing or testing
this checkpoint.

## Console-target validation

The prior process-plan correction stopped executing pip-generated console wrappers. This
checkpoint adds the corresponding root internal validator. For the exact
ValidateConsoleEntryPointTarget action it:

- validates the module and callable as bounded dotted Python identifiers;
- reconstructs the one canonical module:callable target;
- recomputes its SHA-256 and requires the process-plan target digest;
- binds the exact action index and process-plan digest in canonical observation bytes; and
- records that no wrapper path, execution authority, or sync-back was used.

Malformed identifiers, target rebinding, a wrong action index, or a different internal/process
action fail closed.

## Sensor-mandatory supervisor boundary

LinuxVzPackageProtectedProcessObserverV1 is a public but crate-sealed interface. Code outside the
crate cannot implement it, and the crate currently exports no concrete production observer. The
supervisor therefore cannot be called by a package-facing or general external caller.

For each process action the supervisor now requires this order:

1. burn the exact one-attempt process action;
2. remeasure the exact executable, measured inputs, and working directory;
3. create and configure the dedicated cgroup v2 directory;
4. arm the protected observer with the exact launch contract and cgroup descriptor;
5. fork a child that remains blocked in root-controlled setup;
6. attach the exact leader PID to the cgroup;
7. require the observer to correlate that leader before releasing it;
8. execute, bound output, enforce deadline/rlimits/cgroup limits, terminate descendants, reap, and
   prove the cgroup empty;
9. finalize protected observation while the empty cgroup still exists;
10. require a complete correlation record and exact detailed-payload hashes;
11. remove the cgroup, repeat the file measurements, and emit supervisor evidence; and
12. abort the observer on every failure after arming, treating abort failure as a distinct sensor
   teardown failure.

The protected sensor correlation record binds:

- a fresh sensor-session challenge;
- process-plan, launch-contract, and action identities;
- the fixed cgroup name, discovered cgroup ID, and exact leader PID;
- sensor/process start and end monotonic times;
- one global ordered event range and separate process, file, and network counts;
- complete process, file, and network payload digests;
- heartbeat, drop, truncation, health, correlation, descendant, and sensor-teardown state; and
- package UID/GID 65534, no public route, and no sync-back.

It rejects a stale challenge, action/cgroup/PID rebinding, noncanonical JSON, inconsistent counts,
fewer than the required process lifecycle events, missing payloads, payload-digest mismatch,
unhealthy or truncated sensors, any dropped event, incomplete teardown, or invalid time ordering.

The supervisor evidence now includes the accepted sensor-correlation digest. The combined observed
process object retains the complete bounded process, file, and network sensor payload bytes for the
future authenticated evidence envelope; Debug output does not render those bytes.

## Root execution sequencer

execute_linux_vz_package_sequence_v1 is compiled only for Linux. It requires:

- a structurally validated one-use package execution request;
- the exact derived process plan;
- a protected exact-artifact descriptor;
- exactly one closure-payload descriptor when and only when the sdist plan requires it; and
- the crate-sealed protected observer.

The sequencer validates the action graph before creating a workspace. It requires exactly one
first MaterializeExactArtifact action, at least one process, no duplicated source/closure/derived
materializations, and correct source -> closure -> build -> derived-wheel prerequisites.

It then:

1. consumes the validated request into the one-attempt process authority;
2. creates the fixed fresh tmpfs workspace and whole-scenario monotonic deadline;
3. materializes and rehashes the exact artifact;
4. safely materializes a normalized sdist source and exact offline closure when required;
5. validates and seals exactly one derived wheel before any derived-wheel install;
6. validates console targets without trusting generated wrappers;
7. verifies workspace and immutable inputs before and after every process;
8. derives each fixed launch contract, measures it, and invokes only the sensor-mandatory
   supervisor;
9. stops immediately after an exited-nonzero, signaled, or deadline-ended process so later
   prerequisites/probes cannot run on invalid state;
10. retains the complete observed-process evidence for every process that did run;
11. performs final workspace, artifact, closure, and derived-wheel verification; and
12. drops retained package-owned source/output handles, explicitly removes immutable staged inputs,
    unmounts the tmpfs, and emits a transcript only if cleanup succeeds.

An early process failure is an observed ProcessFailed terminal, not a clean run and not permission
to skip evidence. Internal validation, measurement, sensor, rehash, or cleanup failures return an
error and cannot mint a transcript.

## Transcript claim boundary

The canonical transcript binds the request, grant, attempt, plan, artifact, initial/final workspace,
artifact inode/rehash, optional sdist and closure materialization, optional derived wheel, all
console validations, every supervisor record, every protected sensor correlation, action coverage,
terminal state, and successful cleanup.

It also fixes these claims:

- execution_attempt_consumed=true;
- public_network_route_present=false;
- sync_back=false;
- authenticated=false; and
- verdict_eligible=false.

Those last two fields are important. The transcript is an orchestration record, not an
EvidenceEnvelope, detection, or verdict. A missing observer implementation cannot be replaced by a
no-op observer because the interface is sealed, and a future observer cannot claim complete
coverage without detailed payload hashes matching the accepted correlation.

## Verification

Verification used source-level compilation and deterministic inert unit fixtures only:

- whoathere-macos-vm: 146 native library tests passed;
- the console validator accepts the exact reconstructed target and rejects malformed, rebound, and
  wrong-action inputs;
- the sensor-correlation tests accept a fresh exact cgroup/leader record and reject noncanonical,
  stale, unhealthy, dropped, rebound, timing/count, and detailed-payload digest failures;
- the sequence tests prove the npm plan requires one materialization, one process, and no closure;
  the sdist plan requires source, exact closure, build, and derived-wheel order; and sequence
  transcripts are explicitly unauthenticated and verdict-ineligible;
- native warnings-denied Clippy passed for all whoathere-macos-vm targets;
- Linux/aarch64-musl warnings-denied Clippy passed for all whoathere-macos-vm targets, including the
  production root sequencer and mandatory observer callbacks; and
- the full repository Rust suite passed after these changes.

The Linux production path was cross-compiled only. It was not invoked because no protected observer
implementation exists and because local package execution is outside this checkpoint.

## Malware handling boundary

Real malware runs only on the approved cloud Mac under the restricted lab workflow, inside a fresh
disposable Linux VZ clone. This checkpoint did not access the cloud Mac and did not download,
transfer, inspect, unpack, or execute a real sample. It did not run a package locally, start a VM,
use Docker for detonation, enable sync-back, contact live C2, or fetch a second stage.

## Remaining gate

The next execution-path work is concrete and still substantial:

1. define strict arbitrary-package process, file/canary, DNS/connection, and network-frame payload
   schemas rather than accepting only their correlated digests;
2. implement the immutable root sensor service and protected channel that is the first production
   implementor of the sealed observer;
3. bind the qualified telemetry backend and measured sensor binary into that constructor;
4. sign the complete guest transcript and detailed payloads, then bind them to the host VM lifecycle
   receipt;
5. rebuild the exact Linux/aarch64 execution runner, sensor, guest image, and runtime record;
6. independently qualify the new execution-capable runtime; and
7. only then run inert npm CI=false/true, exact wheel, and nested-sdist trigger cases inside fresh
   Linux VZ clones on the approved cloud Mac.

This checkpoint does not improve the current 7/11 malicious-package detection score. Restricted
real-malware regression remains a later separately approved gate and must run only on the cloud Mac
inside disposable Linux VZ guests.
