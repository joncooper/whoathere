# Artifact-Native Linux VZ Closed Execution Program Checkpoint

Date: 2026-07-13

Status: every validated package request derives one canonical ordered semantic program, but no
process launcher or package execution exists yet

## Outcome

The Linux package runner now derives a second closed object after independently validating the
canonical request and exact artifact. This execution program converts the request's one typed
operation into the complete ordered prerequisite and probe sequence the future measured process
launcher must implement.

The program remains explicitly non-authorizing. Its canonical wire says
`execution_authority:false`, `package_execution:false`, and `sync_back_policy:structurally_absent`.
The runner's protected validation report binds the program digest and stage count but still exits
without invoking a package manager or package-controlled code.

## Fixed program boundary

Every program binds:

- the execution-request, artifact, selected template, attempt, and clone digests;
- artifact ecosystem and typed operation;
- root-created read-only named-file materialization from the already rehashed descriptor;
- a fresh UID/GID-owned tmpfs workspace per scenario;
- UID/GID 65534;
- no public route;
- the exact scenario limits;
- an ordered typed stage list;
- no arbitrary-command field; and
- structurally absent sync-back.

There is no executable, argv vector, caller working directory, artifact path, or shell fragment in
the program. The future runner will own the only mapping from these semantic variants to measured
executables and fixed arguments.

npm lifecycle scripts are the intended behavior trigger, so npm may eventually invoke the package
manifest's install hooks and their package-supplied shell semantics inside the untrusted cgroup.
That is distinct from accepting a caller-selected runner shell or command.

## Ordered npm and wheel stages

An npm request derives exactly one stage:

1. install the exact local `package.tgz` offline under either the typed `ci_false` or `ci_true`
   environment, with dependency-free and manifest-install-hook-only policy.

Every wheel request begins with:

1. create a fresh wheel virtual environment; and
2. use pip with no index and no dependencies to install the exact digest-bound wheel basename and
   package identity.

Only then may it add one selected probe:

- start a fresh interpreter to exercise the bound `.pth` files;
- import the validated module root; or
- invoke the validated console entry point with the fixed help-only profile.

The install-only scenario stops after the first two stages.

## Ordered sdist stages

Every sdist request begins with all of these stages:

1. safely extract the exact tar-gzip or ZIP input;
2. create a fresh build virtual environment;
3. install only the exact digest-bound build closure with no index;
4. invoke the exact bound PEP 517 or legacy build recipe; and
5. require and validate exactly one derived wheel.

An inspect scenario then inspects that wheel's metadata. An install scenario creates a distinct
fresh install environment and installs the derived wheel with no index and no dependencies. An
import scenario performs those install stages before importing the validated module root.

This ensures a fresh clone never assumes mutable output from a prior scenario.

## Verification

Rust tests cover:

- the exact npm stage;
- wheel install-before-probe ordering;
- sdist build-and-validate-before-import ordering;
- rejection of a non-sdist archive form; and
- canonical end-to-end derivation from an exact inert npm request.

The macOS/Linux VZ library passes 113 tests, the runner's two native tests pass, and warnings-denied
Clippy is clean. Two clean offline aarch64 builds produced the same stripped static runner:

- byte length: `956344`;
- SHA-256: `c6917c9dc8990d7c6ef74979ff8823f8111ba5d9deaacc3add768f7192caf75d`.

The fixed false-authority probe passed in the pinned Alpine container with `--network none`, a
read-only container filesystem, and no package input.

## Malware handling boundary

Real malware runs only on the approved cloud Mac under the restricted lab workflow. This
checkpoint used Rust source, synthetic digests, and inert fixtures only. It did not download,
inspect, unpack, transfer, or execute a real sample; invoke npm, pip, or Python against a package;
start a VM; enable sync-back; or configure an external route.

## Claim boundary and next gate

This makes execution order reviewable but does not improve the current 7/11 malicious-package
result. Still required are:

- the exact measured executable, argument, environment, and file-descriptor mapping for each stage;
- a root-owned materializer that proves the fixed input name refers to the rehashed descriptor;
- safe sdist extraction and exact build-closure staging;
- bounded output and per-stage results;
- cgroup resource enforcement, sensor correlation, descendant teardown, and signed evidence;
- a distinct reproducible execution-runtime image; and
- physical qualification with exact inert npm, wheel, and nested-sdist fixtures in fresh VZ clones
  on the approved cloud Mac.

Real samples remain later, after that inert execution runtime is qualified.
