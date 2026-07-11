# Artifact-Native Wheel Authenticated Transport Checkpoint

Date: 2026-07-10

Status: distinct Rust and Swift wheel-submission transport implemented with exact-byte streaming,
strict cross-language validation, and pre-issued challenge binding; helper command integration,
VSOCK forwarding, guest staging, Python/pip execution, VM telemetry, and behavioral detection are
not implemented by this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Scenario Compiler Checkpoint](artifact-native-wheel-scenario-compiler-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Mac Run-Spec Checkpoint](artifact-native-wheel-mac-run-spec-checkpoint-2026-07-10.md)
- [Artifact-Native npm Mac Run-Spec and Transport Checkpoint](artifact-native-npm-mac-run-spec-transport-checkpoint-2026-07-10.md)

## Outcome

`whoathere-macos-vm` now has a wheel-specific binary-submission contract rather than routing a
wheel through the npm frame. Its fixed prefix is:

```text
WHOAWHE1 | version:u16 | frame_type:u16 | header_len:u32 |
artifact_len:u64 | artifact_sha256[32] | canonical_header | exact_wheel_bytes
```

All integers use network byte order. The bounded canonical header contains the complete
`whoathere.macos_wheel_run_spec.v1`, its digest, the exact original wheel digest and length, the
fixed 64 MiB artifact ceiling, and challenge/execution bindings. The frame contains no path,
free-form command, registry coordinate, output-copy instruction, verdict, or admission authority.

The Rust writer validates the complete immutable byte slice before emitting the prefix and streams
the raw bytes directly to a caller-provided `Write` sink. The Rust reference decoder independently
checks the fixed prefix, canonical header, complete nested run spec, expected bindings, exact wheel
length and digest, truncation, and trailing data.

The Swift helper core now implements the corresponding incremental reader. It retains only the
bounded prefix/header and one artifact chunk at a time, validates the complete wheel run spec and
all nested digests, and exposes the exact artifact stream once to a future lifecycle forwarding
layer. Consuming a second time fails closed. The completed observation is returned only after the
declared byte count has been read, hashed, matched, and followed by EOF.

This checkpoint does not register a wheel helper command and does not write, install, import, or
execute the wheel. It establishes the authenticated host-to-helper input boundary needed before
those actions can be introduced.

## Binding and ecosystem separation

The wheel execution binding is derived from a wheel-specific domain separator, a challenge-binding
digest, and the complete wheel run-spec digest. The Rust decoder receives the trusted expected
challenge/execution bindings. The Swift reader can receive the pre-issued expected challenge and
rejects a frame whose internally consistent challenge differs.

The Swift parser also rederives and checks the execution binding. Consequently, changing the
artifact, scenario template, base image, helper, supervisor, package account, Python or pip
measurement, guest protocol, or challenge changes a checked digest or fails validation.

The wheel frame uses `WHOAWHE1`,
`whoathere.macos_wheel_submission_header.v1`, and
`whoathere.macos_wheel_submission_execution_binding.v1`. The npm frame uses its own magic, schema,
and binding domain. Rust and Swift tests prove that each parser rejects the other ecosystem's
frame. A wheel cannot inherit npm lifecycle semantics merely by changing an ecosystem label.

This binding check is an input-authentication primitive, not the complete durable challenge
authority. Atomic reservation, single-use consumption, replay prevention, and protected authority
state must be supplied when the wheel path is integrated with the existing disposable lifecycle.

## Strict wheel validation

Before exposing artifact bytes, the Swift decoder requires exact closed key sets and canonical JSON
through the header, run spec, backend identity, template, package subject, runtime profile,
dependency closure, scenario, limits, and evidence requirements. It rechecks:

- the exact wheel artifact, envelope, manifest, and CAS identities;
- PyPI ecosystem identity and wheel-specific guest protocol;
- the measured Python executable and pip CLI versions and digests;
- the stopped-base, helper, supervisor, guest-auth key, runner, and clone measurements;
- the dedicated `_whoatherepkg` name and nonzero bounded UID/GID;
- zero network devices, APFS clone-only operation, one boot/one scenario, and clone destruction;
- a fresh virtual environment, `--no-index --no-deps`, and a fresh interpreter per probe;
- the fixed offline wheel-runner template and empty digest-bound dependency closure;
- positive bounded resource ceilings and the exact required-evidence list; and
- one of the four typed scenario forms: exact install, `.pth` processing, import root, or console
  entry point.

Unknown fields, including an attempted `sync_back`, fail strict decoding. Invalid import/callable
targets, wrong package accounts, schema substitution, binding-domain substitution, noncanonical
headers, artifact mutation, truncation, and trailing bytes also fail closed.

## Structural no-sync posture

Neither the wheel scenario template, Mac run spec, submission header, binary frame, Swift prelude,
nor transport observation has a sync-back field or output-copy capability. The Swift reader returns
only validated identities and measurements; artifact bytes can flow only to the supplied bounded
forwarding closure.

No code in this checkpoint invokes the legacy project sync implementation. A future wheel
lifecycle path must keep the existing artifact-job no-sync invariant structural rather than
depending on a runtime Boolean.

## Verification

The following gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel Mac integration tests | 5 passed, 0 failed |
| `whoathere-macos-vm` tests | 33 passed, 0 failed |
| Full Rust workspace tests, including compile-fail doc tests | 704 passed, 0 failed |
| Swift helper core tests | 36 passed, 0 failed |
| Swift release build | passed |
| Workspace Clippy with warnings denied | passed |
| Rustdoc with warnings denied | passed |
| Rust formatting | passed |

The test suites cover all four wheel scenario variants, exact one-pass streaming, pre-issued
challenge agreement and disagreement, a shared Rust/Swift execution-binding golden, npm/wheel
mutual rejection, mutation, truncation, trailing data, unknown fields, binding-domain substitution,
cross-schema content, wrong package identity, and invalid trigger targets.

All package bytes were small inert repository-generated fixtures. No restricted sample, public
registry, network, cloud Mac, Virtualization.framework VM, VSOCK guest session, Python process, pip
process, package import, console entry point, or package-controlled code was used.

## Open gates

This transport checkpoint advances AN-401 and the wheel side of AN-403, but it does not complete
either work package or the M3 detonation gate. The next required work is:

1. add a separate wheel helper command/lifecycle entry that requires an atomically reserved
   pre-issued binding before any mutable action;
2. forward the exact stream over a wheel-specific VSOCK protocol without a second full host copy;
3. authenticate the wheel guest session and stage the exact wheel in a fresh private root without
   executing it;
4. extend stopped-base provisioning receipts to prove the measured Python, pip, fixed runner, and
   dedicated package account actually exist;
5. implement the root-owned fixed runner and verified privilege drop to `_whoatherepkg`;
6. execute exact install, fresh-interpreter `.pth`, import-root, and console-entry scenarios in
   one-scenario zero-NIC disposable clones; and
7. produce protected process, file/canary, network-intent, sensor-health, teardown, and authenticated
   evidence before making any behavioral-detection or observed-clean claim.

The cloud-Mac host-key trust gate remains open. SSH host-key verification has not been bypassed.
Cloudflare or AWS work remains intentionally downstream of local detection credibility.
