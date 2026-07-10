# Artifact Review v2 Local Runtime Checkpoint

Date: 2026-07-09

Status: macOS-only, caller-authorized inert-provider runtime checkpoint; not an authenticated
provider, model-quality, host-sandbox, VM, malware-execution, detection-quality, or release-readiness
claim

Canonical plan:
[Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)

Prior checkpoint:
[Artifact Review v2 Deterministic Normalizer Checkpoint](artifact-review-v2-normalizer-checkpoint-2026-07-09.md)

## Executive summary

WhoaThere now has an exact provider-input wire and a bounded local process runtime for the compiled
Artifact Review v2 inert fixture. The runtime binds one authorization to the exact review-request,
provider-adapter, synthetic fixture-behavior, and executable-byte digests; constructs the canonical
provider input before any provider work; launches without a shell or `PATH` lookup; exposes only
stdin, stdout, and stderr to the child; enforces wall-clock and stream ceilings; keeps stdout and
stderr separate; tears down and verifies a dedicated macOS process group; preserves valid earlier
outputs if a later runtime operation fails; and explicitly verifies removal of its private run
directory.

The resulting captures feed the existing deterministic normalizer. Timeout, cancellation, nonzero
exit, malformed output, output truncation, a lingering process-group member, missing work, and
partial runtime failure all remain `Uncertain`. Runtime records and normalized results remain
unauthenticated, and `can_authorize_allow()` remains unconditionally false.

This is a provider-process prototype, not the package-detonation boundary. It does not run package
install, build, import, entry-point, or lifecycle code. It does not provide a host sandbox, VM,
network isolation, memory or process-count limits, or containment of descendants that escape the
dedicated process group. No real AI provider or model was invoked. No malware was downloaded,
opened, unpacked, inspected, or executed, and the restricted eleven-sample corpus was not accessed.

## Canonical provider input

Each work item now has one deterministic
`whoathere.artifact_review_provider_input.v2` JSON input. Its top-level projections keep the fixed
control-plane material separate from package-controlled bytes:

- schema, work-item, and invocation identities;
- trusted provider, model, prompt, inference, and privacy settings;
- trusted artifact, manifest, analysis, coverage, policy, template, and result-schema bindings; and
- untrusted normalized path, exact selected source/chunk/context bytes, and validated ranges.

The input includes no CAS path, host filesystem path, runtime directory, or adapter-result schema
body. Construction self-validates the file, chunk, work-item, invocation, line, and byte-range
relationships before serialization. The complete canonical input is capped at 256 KiB and has its
own SHA-256; both the digest and byte length are recorded for each attempted invocation.

The inert runtime uses a single stdin transport, so every output is honestly labeled
`CollapsedPrompt`. The JSON projections preserve semantic trusted/untrusted separation for a future
provider that supports independent roles, but this process adapter does not pretend the transport
itself provides separate channels.

## Request-bound fixture authorization

The only public constructor in this slice accepts the fixed inert-fixture protocol and exact
allowlisted fixture behavior ids. It binds:

- the complete request SHA-256, including artifact, manifest, policy, coverage, prompt, provider,
  model, privacy, and inference identities;
- the provider adapter id, version, and executable-byte SHA-256;
- an allowlisted synthetic fixture-behavior id and version; and
- a domain-separated synthetic behavior digest derived from the verified adapter digest, behavior
  id, and behavior version.

The behavior digest is explicitly synthetic. It is not a hash of model weights and does not attest
that an independent authority reviewed the executable. The executable is caller-authorized, and
both the authorization and all invocation records return `is_authenticated() == false`.

Before launch, the runtime rejects relative paths, symlinks, nonregular files, wrong ownership,
missing execute permission, group/other-writable files, special mode bits, empty or oversized
executables, and digest mismatch. It copies the exact bytes into a private `0500` run path, reopens
and rehashes the staged file, holds its inode open, and revalidates the inode and bytes immediately
before and after each spawn.

macOS cannot execute this fixture through `/dev/fd`, and this prototype does not own a root- or
hypervisor-protected immutable executable store. A same-user process can therefore still race the
staged pathname. Invocation records expose
`DigestVerifiedPrivateStagedPathSameUserRaceNotExcluded`; no stronger executable-identity claim is
made.

## Explicit macOS launch boundary

The runtime uses `posix_spawn` directly rather than the standard `Command` fallback:

- `POSIX_SPAWN_CLOEXEC_DEFAULT` closes every unlisted parent descriptor;
- file actions create only child stdin, stdout, and stderr;
- `POSIX_SPAWN_SETPGROUP` creates the dedicated process group atomically;
- the executable path and sole protocol argument are fixed and NUL-checked;
- the working directory, home, and temporary directory are fresh private directories;
- the environment is rebuilt from exactly `HOME`, `TMPDIR`, `LANG=C`, `LC_ALL=C`, and `TZ=UTC`;
  and
- no shell, `PATH`, package manager, HTTP client, registry client, model server, or provider SDK is
  involved.

The descriptor test is non-vacuous: its positive control deliberately duplicates a regular-file
sentinel to child descriptor 200 and proves the fixture detects it. The runtime negative control
then proves the same cleared-`CLOEXEC` parent descriptor is absent across the explicit spawn
boundary.

## Lifecycle and process-group cleanup

The fixture writes a fixed readiness marker after installing its signal posture and before parsing
stdin. The global deadline starts at runtime entry. The per-call clock starts only after the exact
readiness marker, avoiding the former race in which a test timeout could deliver `SIGTERM` before
the fixture reached `main`. A missing marker cannot be treated as completion.

The runtime does not call `Child::try_wait`, which reaps a Unix child. Instead it:

1. observes leader exit with `waitid(P_PID, ..., WEXITED | WNOHANG | WNOWAIT)`;
2. keeps the leader waitable so its PID/process-group identity cannot be reused during cleanup;
3. queries `proc_listpgrppids` with bounded growing storage, correct PID-count semantics, explicit
   errno checking, and a requirement that the anchored leader remain present;
4. classifies a live nonleader member after leader exit as `LingeringProcessGroup` and a failed
   provider output;
5. closes stdin, sends `SIGTERM`, then sends `SIGKILL` once after the bounded grace period when a
   target remains;
6. requires a final original-group scan with no nonleader member; and
7. reaps exactly once with `waitpid`, after which all signaling and group queries are rejected.

This proves cleanup of the original dedicated process group. It does not prove containment of a
child that calls `setsid` or otherwise escapes that group. Every invocation record therefore says
`process_group_cleanup_verified == true` only when that group was proved clean, while separately
recording `descendant_containment_verified == false`.

## Bounds, partial results, and cleanup

Current enforced ceilings are:

| Resource | Ceiling or posture | Boundary behavior |
| --- | ---: | --- |
| Provider executable | 64 MiB | reject before launch |
| Canonical input per work item | 256 KiB | reject during preflight |
| Canonical inputs per run | 64 MiB | retain a bounded plan prefix; suffix is unattempted |
| Stdout per work item | 256 KiB | retain exactly the bounded prefix as `Truncated` |
| Stdout per run | 8 MiB | suffix is unattempted |
| Stderr per work item | 64 KiB | failed output at overflow |
| Stderr per run | 2 MiB | suffix is unattempted |
| Per-call timeout | configurable, at most 5 minutes | TERM, bounded KILL escalation, failed output |
| Global timeout | configurable, at most 30 minutes | stop dispatch, tear down, suffix unattempted |
| Termination grace | configurable, at most 5 seconds | one bounded KILL escalation |
| Parent descriptor inheritance | explicit stdio allowlist | every unlisted descriptor closed by spawn |
| Memory, CPU, file-size, open-FD count, and process count | not enforced | explicitly recorded limitation |

All deterministic invocation construction and provider-input serialization happen before process
execution, so a later deterministic error cannot erase an earlier positive. After dispatch starts,
directory, spawn/control, capture-construction, and cleanup failures return a typed partial run with
the valid output/record prefix, a terminal error and bound work-item id where applicable, and exact
unattempted work-item ids. `is_dispatch_complete()` describes only whether every planned provider
item was dispatched without a runtime/cleanup error; it is explicitly not a clean or safe verdict.

The run directory has an explicit fallible cleanup step. Success is returned with
`run_directory_cleanup_verified == true` only after the owned path is absent. A primary runtime
error is retained if cleanup also fails, and the cleanup failure is recorded separately. `Drop`
exists only as emergency best-effort cleanup and is not the evidence used for the successful
cleanup claim.

## Authority boundary

The process runtime observes bytes and operating-system state but does not authenticate those
observations. There is no trusted producer key, signature/MAC, freshness proof, replay store, or
independent model-weight attestation in this slice. The host and network postures are explicitly
`NotSandboxedCallerAuthorizedExecutable` and
`NotEnforcedCallerAuthorizedExecutable`. Resource posture is explicitly
`WallClockStreamCapsAndDescriptorClosureOnly`.

Consequently:

- runtime and structural results are advisory;
- a validated suspicious finding may support blocking or escalation;
- provider completion and `no_finding` do not establish safety;
- missing, failed, malformed, truncated, partial, or timed-out work remains uncertain; and
- neither this runtime nor its normalizer can authorize package admission or sync-back.

## Focused verification

All focused tests use inert npm bytes, synthetic source text, synthetic model JSON, and the compiled
inert provider. No network or real model is involved.

| Suite | Result | Covered behavior |
| --- | ---: | --- |
| Runtime unit tests | 2 passed | explicit/fail-closed directory cleanup; unreaped leader observation; post-reap API rejection |
| Runtime integration tests | 9 passed | exact binding and normalization; fixed environment; stderr separation; stdout/stderr caps; readiness, timeout, cancellation, TERM/KILL, and lingering-group handling; malformed/nonzero failure; authorization and executable substitution; positive/negative descriptor inheritance; partial-result preservation; pre-dispatch cancellation |
| Detector Artifact Review suites | 25 passed | canonical provider input, strict normalizer, npm/wheel/sdist coverage, request/model/inference binding, prompt/data separation, and no-allow authority |

Focused runtime tests, Clippy with warnings denied, rustdoc with warnings denied, formatting, and
`git diff --check` passed. Two independent adversarial reviews returned `PASS` after the descriptor
positive control exposed and drove replacement of the original leaking launch path with the
explicit `posix_spawn` boundary.

The full workspace regression gate passed 635 Rust unit and integration tests with zero failures.
These are implementation checks only, not provider quality, VM isolation, benign-friction,
held-out, restricted-corpus, or release gates.

## Remaining work

1. Replace unauthenticated caller assertions with trusted producer/key resolution, signed or
   MAC-bound request/invocation/capture/result identities, freshness, replay protection, and atomic
   verification before evidence can affect admission.
2. Add real provider adapters behind the provider-neutral interface and qualify their exact model
   identity, token accounting, privacy posture, cancellation, and structured-output behavior. A
   provider/model run is a separate qualification gate and did not occur here.
3. Decide whether a production local provider needs a root-protected immutable executable store,
   code-signing requirement, sandbox, supervisor-applied memory/process limits, or an XPC boundary;
   the prototype's same-user path race and resource limitations remain open.
4. Complete aggregate graph, version-diff, synthesis, tokenizer-budget, and cross-language
   canonical-wire work without allowing incomplete coverage to become clean.
5. Move package-controlled execution to fresh disposable VMs, rehash exact artifacts inside the
   guest, compile typed npm/wheel/sdist scenarios, run package code unprivileged, and collect
   protected process/file/network telemetry with authenticated provenance and no sync-back.
6. Run benign and held-out gates, then use only the separately approved restricted-lab workflow for
   the four prior misses and complete eleven-sample regression. This goal still does not authorize
   real-malware execution.

The available cloud Mac can be used for a second-host reproducibility run, provider-process
conformance, and later inert VM lifecycle/telemetry tests. It must not be used as an informal
malware detonation host. Cloudflare Sandbox/Containers and managed AWS MicroVM evaluation remain
after the local Mac execution and evidence contracts are detection-credible.
