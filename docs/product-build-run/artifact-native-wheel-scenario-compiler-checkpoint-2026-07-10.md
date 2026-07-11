# Artifact-Native Wheel Scenario Compiler Checkpoint

Date: 2026-07-10

Status: exact dependency-free wheel metadata compiles into a closed, deterministic, no-sync
scenario plan; no wheel, pip, Python probe, or VM was executed in this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native npm VM First-Slice Plan](artifact-native-npm-vm-first-slice-plan-2026-07-10.md)
- [Artifact-Native npm Scenario Compiler Checkpoint](artifact-native-npm-scenario-compiler-checkpoint-2026-07-10.md)

## Outcome

`whoathere-detonation` now has a wheel-specific compiler contract rather than pretending the
npm-only V1 schema covers PyPI. A completely normalized, dependency-free, pure-Python wheel
deterministically produces this ordered matrix:

1. install the exact wheel;
2. when `.pth` files exist, launch a fresh interpreter and bind the complete ordered `.pth` file-id
   set;
3. install and import each validated top-level import root in its own scenario; and
4. install and invoke each validated console entry point with the fixed `help_only` argument
   profile.

Every scenario wire declares a fresh virtual environment, the typed `no_index_no_dependencies`
resolver policy, and a fresh interpreter per probe. These are canonical contract fields, not claims
that execution already occurred and not free-form commands. The guest implementation will map the
fields to a fixed root-owned runner; package metadata cannot supply argv, a shell string, a
registry, a host path, or a command template.

## Exact identity and runtime binding

Each template binds:

- original wheel digest and byte length;
- envelope, manifest, and immutable CAS identities;
- normalized PyPI name and version;
- policy digest;
- distinct job, run, evidence, and scenario IDs;
- measured Python executable and pip CLI digests and versions;
- the fixed offline wheel-runner template digest;
- the manifest-bound empty dependency-closure digest;
- zero configured network devices;
- the dedicated unprivileged package UID/GID boundary;
- required transport, guest rehash, process, listener, sensor, VM-stop, channel-closure, and clone
  destruction evidence; and
- mandatory disposable-clone destruction.

Changing one wheel byte, the trusted scenario IDs, the Python/pip runtime, the policy, or any
subject identity changes the applicable template and plan digests or fails compilation.

The template and plan schemas have strict canonical JSON decoders. Unknown, duplicate, trailing,
noncanonical, reordered, malformed, or tampered data fails closed. Console target digests are
recomputed from validated dotted Python module and callable identifiers, so a target digest cannot
be substituted independently.

## Metadata and unsupported-shape gates

Compilation rechecks the normalized wheel contract rather than trusting metadata presence alone.
It requires one safe `.dist-info` directory, `METADATA`, `WHEEL`, and complete `RECORD` identities,
Wheel 1.0, a root placement flag, tags, and agreement between the generic and console-specific
entry-point maps. Console targets with extras, whitespace, invalid identifiers, or unsafe command
names fail before any backend.

This first executable wheel shape deliberately fails closed for:

- any `Requires-Dist` or envelope requiring external resolution;
- any native tag or native binary inventory;
- raw wheel `.data/scripts` members;
- invalid import roots or console targets;
- incomplete normalization;
- missing or extra trusted scenario identities; and
- artifact, envelope, manifest, CAS, or policy mismatch.

Those cases are not reported as malware detections. They are explicit unsupported or invalid
execution shapes pending digest-bound dependency closure, native-platform qualification, and typed
raw-script handling.

## Structural no-sync boundary

The wheel policy, template, plan, scenario kinds, decoders, and validated observations expose no
sync-back option or guest-file return path. Adding `sync_back` to canonical wire is an unknown-field
error. The only terminal disk disposition is clone destruction.

## Verification

| Gate | Result |
| --- | --- |
| Wheel compiler integration tests | 5 passed, 0 failed |
| `whoathere-detonation` tests | 13 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 699 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |
| Swift helper core tests | 31 passed, 0 failed |

The tests generate inert wheel ZIP bytes in memory with a complete hash-checked `RECORD`. They prove
the four-scenario matrix, exact-byte/runtime/identity rebinding, closed canonical template and plan
wire, subject and policy mismatch rejection, complete identity-set enforcement, and fail-closed
handling for dependencies, native members, raw scripts, invalid entry targets, forged target and
closure digests, unknown sync fields, and reordered plans.

No restricted sample, network, registry, cloud Mac, VM, guest process, pip process, Python import,
or package code was used.

## Open gates

This checkpoint implements the compiler half of `AN-403`, not the guest workflow or detection
claim. Remaining work includes:

1. translate the validated wheel wire into the authenticated Mac run spec without adding generic
   argv or sync options;
2. provision and measure the Python/pip runtime in the stopped base;
3. implement the root-owned guest wheel runner and reviewed package-account privilege drop;
4. prove exact-wheel `pip --no-index --no-deps` installation and fresh-interpreter `.pth`, import,
   and console triggers in disposable zero-NIC clones;
5. add protected process, file, and network telemetry and authenticated behavior evidence;
6. add digest-bound dependency closures, native compatibility classification, raw-script handling,
   and explicitly selected zero-argument API probes;
7. implement the sdist build-to-derived-wheel workflow; and
8. run benign controls and the separately authorized restricted regression campaign only after the
   local execution and telemetry gates are credible.

The disposable cloud Mac remains unavailable until its changed SSH host key is confirmed through a
trusted out-of-band source. SSH host-key verification has not been weakened.
