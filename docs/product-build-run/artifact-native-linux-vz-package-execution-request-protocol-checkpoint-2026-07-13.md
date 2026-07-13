# Artifact-Native Linux VZ Package Execution-Request Protocol Checkpoint

Date: 2026-07-13

Status: a consumed signed grant can derive one closed, exact-byte-bound runner request; the
execution-capable runner, protected launch path, and execution-runtime physical qualification do
not exist yet

## Outcome

WhoaThere now has a second burn-first boundary between a verified package-execution grant and a
future unprivileged package runner. The protected guest agent can consume one non-clonable grant
observation and derive exactly one canonical execution request from the already validated artifact,
scenario plan, and selected scenario template.

No caller supplies the runner operation. It is compiled from the canonical scenario schemas. The
request contains no executable path, artifact path, working directory, argv vector, or shell
fragment.

This checkpoint is protocol-only. It does not modify the current nonexecuting runtime, launch a VM,
run npm or pip, or make the opaque execution-runtime qualification proof constructible.

## Authority chain

The authority sequence is now:

1. Exact package bytes and a canonical scenario plan produce the non-authorizing package request.
2. A future authenticated physical qualification record is required before a signed execution
   grant can be issued.
3. The protected guest verifier burns and verifies that signed grant once.
4. The verified grant observation is moved, not cloned, into a request authorizer.
5. The authorizer burns before artifact or scenario validation and derives one canonical closed
   runner request.
6. A future one-boot protected supervisor must pass that request through a one-use protected
   channel to one unprivileged runner and bind its digest into signed evidence.

An invalid artifact or scenario consumes the authorizer just as a valid derivation does. A second
call returns `already_consumed`.

## Exact bindings

Every derived request binds:

- the complete package-authority request and consumed signed-grant digests;
- the future execution-runtime qualification-record digest;
- exact artifact kind, SHA-256, and byte length;
- for sdists, the exact magic-detected `sdist_tar_gzip` or `sdist_zip` transport form;
- scenario plan, selected template, scenario id, scenario-kind, scenario-policy, dependency- or
  build-closure, and runtime-profile digests;
- request, grant, attempt, and unique-clone bindings;
- grant issue, expiry, and verification times;
- UID/GID 65534;
- the selected scenario limits;
- one exact rehashed read-only artifact descriptor;
- one typed scenario and one attempt;
- no arbitrary command input;
- no public network route; and
- structurally absent sync-back.

The package-authority request retains its false-authority state. Only the already consumed signed
grant permits the derived request to state `package_execution_permitted:true`.

## Closed operation matrix

The current canonical scenario types compile into these runner operations:

| Package scenario | Derived runner operation |
| --- | --- |
| npm local tarball, `CI=false` or `CI=true` | Create a clean consumer and install the exact local tarball under the bound environment profile. |
| Wheel exact install | Install the exact wheel with no index and no dependencies. |
| Wheel `.pth` probe | Bind the install-template digest, install the exact wheel, then start the required fresh interpreter for the validated `.pth` file ids. |
| Wheel import root | Bind the install-template digest, install the exact wheel, then import the validated module in a fresh interpreter. |
| Wheel console entry point | Bind the install-template digest, install the exact wheel, then invoke the validated entry point only with the `help_only` profile. |
| Sdist exact build | Build the exact sdist from the plan-bound PEP 517 or legacy recipe and fixed offline build closure. |
| Sdist derived-wheel inspect | Bind the build-template digest and recipe, build, rehash, and inspect the derived wheel in the same disposable scenario. |
| Sdist derived-wheel install | Bind the build-template digest and recipe, build, rehash, validate, and install the derived wheel in the same disposable scenario. |
| Sdist import root | Bind the build-template digest and recipe, build and install the derived wheel, then import the validated module. |

The composite forms are intentional. A fresh clone cannot depend on mutable output from a previous
scenario. Wheel probes therefore include their exact install prerequisite, and sdist probes include
their exact build prerequisite.

The sdist template also binds the magic-detected archive form. The package-authority boundary
independently rejects gzip/ZIP magic that does not match the template, and the closed build recipe
carries that form forward so the runner never guesses a filename or unpacking mode.

The scenario compiler does not yet emit npm main/export or npm bin probes. They remain required by
the execution plan and must gain canonical templates before they can enter this closed operation
matrix.

## Verification

The focused grant/request suite now proves:

- exact signed-grant identity is carried into the derived request;
- a grant observation is not clonable;
- request authorization burns before artifact or scenario validation;
- retry after any derivation attempt is rejected;
- a wheel probe cannot exist without its plan-bound install prerequisite;
- sdist probes carry the exact plan-bound build recipe and build-template digest;
- the serialized operation surface contains no free-form process interface; and
- exact inert npm tarball bytes normalize into the `CI=true` template and produce one canonical
  request with fixed descriptor input, one attempt, no public route, no arbitrary command input,
  and no sync-back.

The focused execution protocol tests pass, the macOS-VM library suite passes, formatting is clean,
and all-target macOS-VM Clippy passes with warnings denied.

## Malware handling boundary

Real malware runs only on the approved cloud Mac. This checkpoint used repository code and a newly
constructed inert npm fixture. It did not download, inspect, unpack, transfer, or execute any real
sample, invoke a local VM, or use Docker as a detonation environment.

## Remaining gate

The request is not a runner and cannot launch anything. The next gate is a distinct reproducible
execution runtime with:

- a measured root-owned protected agent, sensor, and immutable runner;
- a strict one-request protected transport with replay resistance tied to the one-boot lifecycle;
- fixed implementations for the closed operations above;
- process-group/cgroup teardown and bounded output enforcement;
- signed process, file, network, sensor-health, and destruction evidence;
- an inert qualification probe that proves the runner can reach the intended npm, wheel, and sdist
  triggers without granting a general command interface; and
- authenticated physical qualification of those exact bytes on the approved cloud Mac.

Only after that physical gate may the qualification verifier construct the opaque proof required
by the execution-grant protocol.
