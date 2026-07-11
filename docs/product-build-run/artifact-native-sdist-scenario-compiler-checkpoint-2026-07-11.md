# Artifact-Native sdist Scenario Compiler Checkpoint

Date: 2026-07-11

Status: exact normalized PyPI sdist metadata compiles into a closed, deterministic, no-sync build
and derived-wheel plan; no sdist build, pip command, Python import, package code, VM, or malware was
executed in this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Scenario Compiler Checkpoint](artifact-native-wheel-scenario-compiler-checkpoint-2026-07-10.md)
- [Artifact-Native Inert Wheel VM Qualification Handoff](artifact-native-inert-wheel-vm-qualification-handoff-2026-07-10.md)

## Outcome

`whoathere-detonation` now has an sdist-specific compiler contract for the build-to-wheel portion of
`AN-404`. A completely normalized, pure-Python sdist deterministically produces this ordered matrix:

1. build the exact sdist through its typed PEP 517 backend or legacy `setup.py` path;
2. hash and inspect the derived wheel as an untrusted derived artifact;
3. install the derived wheel in a fresh scenario or environment; and
4. import each validated package root in its own fresh-interpreter scenario.

The build scenario binds the normalized build-backend object reference, ordered in-tree backend
paths, and the digest of the declared build-requirement set. PEP 517 `module` and
`module:object.path` references are accepted only when every dotted component is a valid Python
identifier. Legacy execution is a separate enum variant and cannot carry a PEP 517 backend or
backend path.

This is a scenario-description boundary, not an execution implementation. The guest runner must
still map these fields to fixed root-owned behavior; package metadata cannot supply arbitrary argv,
a shell command, a registry, a host path, or a command template.

## Exact byte, closure, and runtime binding

Each template binds:

- original sdist digest and byte length;
- envelope, manifest, and immutable CAS identities;
- normalized PyPI package name, version, and canonical archive root;
- distinct job, run, evidence, and scenario identities;
- policy digest;
- measured Python executable and pip CLI versions and digests;
- the fixed offline sdist-runner command-template digest;
- the digest-bound, ordered build-tool artifact closure;
- the digest of the exact normalized `build-system.requires` declaration set;
- a fresh isolated build environment and no-index fixed-closure-only resolution;
- denial of dynamic build requirements outside that fixed closure;
- derived-wheel rehash, validation, fresh-scenario use, and no-host-copy disposition;
- zero configured network devices;
- the dedicated unprivileged package UID/GID boundary;
- required transport, guest rehash, process, listener, sensor, VM-stop, channel-closure, clone
  destruction, build-closure, derived-artifact, and build-environment-teardown evidence; and
- mandatory disposable-clone destruction.

Changing one sdist byte, the trusted scenario identities, the Python or pip runtime, the policy,
the build declarations, or any closure artifact changes the applicable template and plan digest or
fails compilation.

The build closure contains exact normalized names, versions, byte lengths, and SHA-256 identities.
Every direct build declaration must be represented in the closure, and the closure declaration
digest must match the normalized sdist. There is no public-index fallback in the typed policy.

## Closed wire and fail-closed gates

Template and plan wires are RFC 8785 canonical JSON with closed schemas and typed enum fields.
Their decoders reject unknown fields, duplicate or trailing JSON, noncanonical encodings, invalid
backend references, mutated build-declaration or closure digests, reordered scenarios, repeated
scenario identities, repeated template digests, and cross-schema substitutions.

The first supported execution shape deliberately fails closed for:

- incomplete or mismatched normalization, artifact, envelope, manifest, CAS, or policy identity;
- a missing `PKG-INFO` or missing build surface;
- invalid or escaping PEP 517 backend paths;
- an incomplete or mismatched fixed build-tool closure;
- runtime `Requires-Dist` dependencies;
- native binary inventory;
- invalid package roots or Python import targets; and
- missing or extra trusted scenario identities.

Those conditions are unsupported or invalid execution shapes, not malware detections. Dynamic PEP
517 build requirements are permitted only under the explicit `deny_outside_fixed_closure` policy;
the future runner must fail and preserve evidence if a backend asks for anything outside the bound
closure.

## Structural no-sync boundary

The sdist policy, scenarios, templates, plans, and validated wire observations expose no sync-back
option and no guest-file return channel. The derived wheel is explicitly classified as
rehash-and-validate input for a fresh disposable scenario and never as a host copy-back candidate.
Adding a `sync_back` field is a closed-schema wire error. The only terminal clone disposition is
destruction.

## Verification

| Gate | Result |
| --- | --- |
| sdist compiler integration tests | 5 passed, 0 failed |
| `whoathere-detonation` tests | 18 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | passed |
| Workspace Clippy with warnings denied | passed |
| Rust formatting | passed |
| Diff whitespace validation | passed |

The tests generate inert nested-root tar/gzip sdists in memory. They cover a normal PEP 517 backend,
a valid `module:object` backend with an in-tree backend path, a distinct legacy setup path,
exact-byte/runtime/identity rebinding, fixed-closure enforcement, closed canonical template and plan
wires, tamper detection, runtime dependency rejection, native-artifact rejection, subject mismatch,
and complete identity-set enforcement.

The initial workspace test attempt was prevented from binding loopback sockets in four existing
Ollama client tests. The full gate was rerun with local-loopback permission and passed. No public
network, registry, cloud Mac, VM, guest process, build backend, pip process, Python import, package
code, restricted sample, or malware was used.

## Claim boundary and open gates

This checkpoint proves a typed compiler and wire-validation boundary only. It does not prove:

- that the Mac backend transports or stages sdist bytes;
- that PEP 517 or legacy builds execute correctly or safely;
- that a derived wheel is captured, normalized, or passed to a second clone;
- that build, process, file, or network behavior is independently observed;
- that authenticated dynamic evidence is emitted or accepted;
- that any malicious or benign package behavior is detected; or
- that the eleven-sample regression, benign-friction, or held-out generalization gates pass.

The next local execution slice is to translate validated sdist templates into a distinct closed Mac
run spec and bounded binary submission protocol, then add authenticated guest staging that rehashes
and removes inert sdist bytes without executing them. Actual build execution comes only after that
non-executing boundary is proven. The pending live wheel qualification remains gated on trusted
confirmation of the cloud Mac's changed SSH host identity; host-key verification has not been
weakened.
