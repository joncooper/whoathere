# Artifact-Native Linux VZ Package Authority-Request Checkpoint

Date: 2026-07-13

Status: exact Linux/arm64 npm, wheel, and sdist scenario bindings are implemented; a qualified
telemetry backend can produce a non-authorizing candidate-runtime request, but package execution
remains structurally unavailable

## Outcome

The artifact-native scenario layer and the qualified Linux VZ telemetry backend now meet at an
explicit fail-closed boundary. A request can bind all of the following without granting execution:

- exact package bytes and byte length;
- artifact, envelope, and normalized-manifest SHA-256 identities;
- canonical typed scenario plan, selected template, scenario kind, policy, and dependency-closure
  identities;
- the package-manager runtime profile and an explicit `linux_arm64` target;
- exact candidate runtime rootfs, runtime-manifest, and package-runner identities;
- the qualified telemetry backend, backend identity, telemetry requirements, and complete
  conformance evidence set;
- a fresh request challenge and dedicated clone binding; and
- fixed raw-byte transport, no-network-device, unprivileged-package, destroy-clone, and
  structurally-absent sync-back policies.

The canonical request says that the candidate runtime exact bytes are not yet independently
qualified. It records `execution_authority_issued: false` and `package_execution_permitted: false`.
There is no capability or execution-grant material in the request type.

## Corrected target mismatch

The existing npm, wheel, and sdist scenario profiles were cryptographically committed to
`macos/arm64`. The qualified lightweight backend is Linux/arm64. Reusing those profiles would have
made a typed plan appear eligible for a runtime it did not name.

`ArtifactRuntimeTargetV1` now makes `macos_arm64` and `linux_arm64` distinct runtime identities.
The existing constructors remain macOS-compatible and retain the prior wire representation.
Target-aware constructors create separate Linux profile, template, policy, and plan digests.
Strict template decoders accept only supported target pairs, require the outer template and inner
runtime target to agree, and recompute the profile digest for that exact target. Cross-target field
changes therefore fail validation.

This is a compatibility extension to the existing V1 scenario schemas, not permission to run a
macOS-bound scenario on Linux.

## Trust boundary

The implementation separates three states that must not be collapsed:

1. A typed Linux scenario binding proves that a canonical plan actually selects the canonical
   template and that their artifact, envelope, manifest, policy, closure, scenario identity, and
   runtime target agree.
2. A package authority request additionally rehashes the exact package bytes and binds a complete
   qualified telemetry record, candidate runtime components, challenge, and clone.
3. A future runtime qualification and one-use execution grant are still required before any package
   command can run.

The first two states expose `package_execution_authority_permitted() == false` and
`sync_back_permitted() == false`. The request verifier reconstructs the expected canonical request
from all exact inputs. Noncanonical JSON, changed artifact bytes, a plan/template mismatch, the
wrong ecosystem decoder, macOS-target templates, rebound challenges or clones, and attempts to set
either authority boolean are rejected.

## Verification

The focused Rust and independent Swift tests prove:

- Linux target profile digests differ from otherwise equivalent macOS profiles for npm, wheel, and
  sdist.
- Linux canonical templates round-trip through strict type-specific decoders.
- macOS-to-Linux target rebinding fails for all three artifact forms.
- all three Linux plan/template selection branches produce a non-authorizing typed binding.
- a template whose scenario identity is changed no longer belongs to its plan.
- a full 38-case qualified backend binds an inert exact npm tarball, Linux plan/template, candidate
  runtime, challenge, and clone into a canonical request.
- an independent decode/rebuild obtains the same request digest.
- changed artifact bytes, a zero challenge, challenge/clone aliasing, a rebound clone,
  noncanonical encoding, and elevated authority fields fail closed.
- the Swift decoder independently enforces canonical encoding, the closed npm/wheel/sdist scenario
  shapes, Linux-only target policy, distinct candidate-runtime identities, challenge/clone
  separation, and the absence of execution and sync-back authority. Rust remains responsible for
  rebuilding the request from the external exact artifact, plan, template, runtime, and qualified
  backend inputs.

The complete verification run passed:

- the full Rust workspace and documentation tests;
- Rust formatting and Clippy for all targets with warnings denied;
- all 188 Swift helper tests; and
- the package-risk, scanner-integration, real-world inert attack, and actual-malware harness
  self-test smoke suites.

No package was executed by this checkpoint. No malware was opened, unpacked, inspected, or run.
No cloud backend was evaluated, and no detection score changed. The known malicious-package result
remains 7 of 11 behavior detections, or 63.6%.

## Next gate

Build a deterministic Linux/arm64 package-runtime image containing pinned Node/npm and Python/pip,
the immutable root package runner, and the already-qualified protected sensor components. Produce
and independently verify a runtime manifest against the actual rootfs and binaries. Only after that
qualification should a one-use execution-grant protocol be added.

The first authorized executions must remain inert and cover exact local npm tarball installation in
both CI profiles, exact wheel installation plus fresh-interpreter probes, and exact sdist build via
the fixed offline closure followed by derived-wheel validation and fresh installation. Each run
must use one disposable clone, no public resolver, no host package-manager execution, complete
authenticated telemetry, proven teardown, and no sync-back.
