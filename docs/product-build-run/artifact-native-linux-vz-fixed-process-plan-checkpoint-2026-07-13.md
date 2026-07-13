# Artifact-Native Linux VZ Fixed Process Plan Checkpoint

Date: 2026-07-13

Status: npm, wheel, and sdist semantic programs derive canonical fixed process plans, but the
runner still has no package-launch authority or process-launch implementation

## Outcome

The protected Linux package runner now derives a third closed object after independently validating
the canonical request, rehashing the exact artifact, and deriving the ordered semantic execution
program. The process plan maps every semantic stage to a fixed executable identity, fixed arguments,
an exact cleared environment, a fixed working directory, bounded captured output policy, or a typed
internal action.

This remains a non-executing boundary. The canonical process plan and runner report say
`execution_authority:false`, `package_execution:false`, and `sync_back:false`. The runner computes
and reports the process-plan digest and action count, then exits without materializing an artifact,
creating a workspace, invoking Node, npm, Python, or pip, or running package-controlled code.

## Exact runtime and process binding

The canonical request and semantic program now preserve the runtime executable identities from the
validated Linux scenario profile:

- Node version, Node executable SHA-256, npm version, and npm CLI SHA-256 for npm; or
- Python version, Python executable SHA-256, pip version, and pip CLI SHA-256 for wheels and sdists.

The process-plan mapping fixes these direct runtime paths:

```text
/usr/bin/node
/usr/lib/node_modules/npm/bin/npm-cli.js
/usr/bin/python3.14
/usr/bin/pip3
```

Every process clears its inherited environment before installing one exact canonical map. Standard
input is null and standard output and error are bounded captured streams. The executable is stored
separately from the argument list; `arguments` contains only values after `argv[0]`, preventing a
future launcher from accidentally passing the executable as a script argument. No caller-supplied
executable, argument, environment variable, working directory, or process path enters this mapping.

The complete measured runtime rootfs remains bound by the authenticated execution-runtime
qualification chain. npm receives the fixed `--script-shell=/bin/sh` option. npm itself may invoke
that measured-rootfs shell for package-declared lifecycle scripts; that is the intended untrusted
behavior trigger, not a caller-selected runner shell.

## Fixed npm plan

The two typed npm profiles map to a measured Node invocation of the measured npm CLI with:

- the exact rehashed local tarball path;
- offline mode;
- no audit, funding, update-notifier, registry resolution, or lockfile write;
- foreground lifecycle scripts and `ignore-scripts=false`;
- a fixed cache, prefix, and lifecycle shell; and
- `CI=true` only for the `ci_true` profile.

The dependency-free policy remains enforced before this plan. The process mapping cannot add a
registry target or a dependency resolver.

## Fixed wheel plan

Every wheel plan first materializes the exact digest-bound normalization-validated wheel basename.
It then:

1. creates a fresh copied virtual environment without pip;
2. invokes the measured pip CLI through the measured base Python interpreter with `--python` aimed
   at that environment, `--no-index`, `--no-deps`, `--no-input`, and `--no-compile`; and
3. optionally runs the selected `.pth`, import-root, or console-entry-point probe through a fresh
   environment interpreter or the exact validated derived console target. A typed internal action
   first checks that a generated console wrapper resolves to the validated `module:callable` target;
   the semantic target digest is deliberately not mislabeled as the wrapper file's byte digest.

The process-plan tests specifically cover the fact that a wheel program's first stage creates the
environment while its exact artifact basename appears in the second stage. Materialization scans
the complete closed program rather than incorrectly assuming the first stage contains the input.

## Fixed sdist plan

The sdist template decoder now preserves the normalization-validated canonical archive root instead
of dropping it at the VM boundary. The request, build recipe, semantic program, and safe-extraction
action all bind that exact root together with the exact tar-gzip or ZIP form.

The process plan then fixes this order:

1. materialize the exact sdist;
2. safely extract only the expected normalized archive root;
3. create a fresh build environment;
4. validate and install only the exact plan-bound build-closure artifacts from fixed local wheel
   paths with no index;
5. invoke the validated PEP 517 backend or legacy `setup.py` recipe using fixed Python code that
   receives validated backend names as data through `sys.argv` and uses neither `eval` nor `exec`;
6. require exactly one derived wheel and inspect its metadata when selected; and
7. for install/import scenarios, create a distinct fresh install environment and pass only a typed
   `ValidatedDerivedWheelPath` slot to pip before the validated import-root probe.

The build closure itself, not only its digest, is now present in the closed request and semantic
program. The runner can therefore stage and rehash each exact closure artifact without performing
fresh dependency resolution.

## Verification

The local verification used only Rust source, synthetic digests, and inert package fixtures:

- `whoathere-detonation` library tests: 2 passed;
- `whoathere-macos-vm` library tests: 118 passed;
- execution-runner native tests: 2 passed;
- warnings-denied Clippy for both affected crates: passed; and
- formatting check: passed.

The repository-wide Rust test suite also passed after its fake Ollama server tests were rerun with
localhost socket binding available; the initial sandboxed attempt failed only because the sandbox
returned `EPERM` for those four test-only loopback binds.

Tests cover both npm CI profiles, exact Node/npm and Python/pip identities, separated executable and
argument semantics, later-stage wheel materialization, console-wrapper validation before execution,
normalized sdist-root preservation, exact build-closure paths, typed derived-wheel substitution,
and fixed Python target handling.

Two clean offline Linux/aarch64 release builds produced byte-identical stripped static runners:

- byte length: `1098504`;
- SHA-256: `46c7c21655fb3c659f7a8ff4b9b53af461c591a19a24698069e3fc54be94f780`.

The fixed false-authority probe passed in the pinned Alpine aarch64 container with `--network none`,
a read-only container filesystem, and no package input. Docker was used only to execute this fixed
identity probe; it was not used as a detonation environment.

## Malware handling boundary

Real malware runs only on the approved cloud Mac under the restricted lab workflow, inside a fresh
disposable Linux VZ clone. This checkpoint did not download, transfer, inspect, unpack, or execute a
real sample. It did not run any package locally, start a VM, enable sync-back, contact live C2, or
fetch a second stage.

## Claim boundary and next gate

This checkpoint makes the process mapping explicit and reviewable. It does not improve the current
7/11 malicious-package detection result, qualify an execution-capable runtime, or support a broad
package-safety claim.

Still required before the first inert package execution are:

- a root-owned artifact and build-closure materializer with post-write rehash and immutable
  ownership/mode checks;
- a traversal-, link-, device-, size-, count-, and root-enforcing sdist extractor;
- a launcher that verifies every pinned executable and measured input immediately before `execve`;
- typed substitution and revalidation of the single derived wheel path;
- per-stage deadlines, output limits, result records, and error semantics;
- cgroup resource enforcement, protected telemetry correlation, descendant teardown, and signed
  evidence; and
- a new reproducible execution-runtime image followed by physical qualification with exact inert
  npm, wheel, and nested-sdist fixtures on the approved cloud Mac.

Real-sample regression runs remain later. They start only after the inert execution runtime and
evidence path pass their physical qualification gates on the cloud Mac.
