# Artifact-Native Linux VZ Package-Sensor Terminal-Binding Checkpoint

Date: 2026-07-14

Status: exact supervisor wait result bound through the protected sensor protocol and evidence
correlation

## Outcome

The protected package-process path no longer asks the sensor to finalize from two loose timestamps.
After the leader has been reaped and the package cgroup is empty, the root supervisor constructs one
validated completion value from the actual `waitpid` result. It admits exactly one of:

- `exited` with one 8-bit exit status and no termination signal; or
- `signaled` with one Linux signal in `1..=64` and no exit status.

The same value binds the nonzero start timestamp and strictly later end timestamp. Invalid or
ambiguous combinations fail before the protected observer can send a finish request.

The sealed observer, root-only control channel, receiving service driver, collector boundary,
correlation decoder, and typed process-payload decoder now carry that completion consistently:

1. the supervisor derives it from the reaped leader's kernel wait status;
2. the finish-v2 request carries the exact terminal kind, optional status/signal, and timestamps;
3. the service revalidates the mutually exclusive shape and gives the typed value to the collector;
4. the finish-v2 acknowledgment must echo the exact value;
5. process-correlation v2 must match the supervisor's value; and
6. the leader `exit` event in typed process evidence must match the correlated status or signal.

A service or evidence producer can no longer substitute exit `0` for a signal, change one exit
status to another, provide both terminal fields, omit both, use signal `0` or a value above `64`, or
rebind the process timing. The old v1 schema identifiers remain declared for provenance, but the
active finish and correlation paths accept only the new v2 schemas.

This closes the protocol/evidence side of the exact-terminal gap exposed by the process-correlator
checkpoint. It does not yet instantiate a production collector, add `exit_code` to the BPF
lifecycle record, or improve the July malicious-package result. The score remains **7/11
(63.6%)**.

## Safety boundary

No package or malware code ran. This checkpoint used only Rust unit tests, native compilation, and
Linux/aarch64 cross-compilation. It did not boot a VM or access restricted evidence.

Real malware remains restricted to the approved cloud Mac and may execute only inside a fresh
disposable Linux VZ guest under the separate approved lab workflow. It must never run in this
workspace, on the Mac host itself, or in Docker; sync-back and live C2 or second-stage retrieval
remain forbidden.

## Trust boundary

The terminal value originates only after the root supervisor has reaped the exact leader PID. The
crate-sealed observer prevents an external implementation from bypassing that construction path.
The receiving service still independently requires:

- the exact launch-contract, process-plan, action, cgroup, and leader binding;
- an empty cgroup before collector finalization;
- canonical finish-v2 framing from the verified root peer;
- an exact completion acknowledgment after evidence frames; and
- zero loss, healthy collectors, complete teardown, no public route, and no sync-back.

The process-correlation decoder independently compares the v2 terminal fields with the
supervisor-derived completion. The typed process decoder then compares the leader's exit event with
the correlated value. A mismatch at either boundary is verdict-ineligible.

## Validation

- Package-sensor Rust library suite: 178 passed.
- Native package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64-musl package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Formatting and `git diff --check`: passed.
- Exact exited and signaled completions: accepted.
- Missing, dual, cross-kind, out-of-range, time-rebound, correlation-rebound, and typed-exit-rebound
  cases: rejected.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Root process supervisor | `sha256:be589f2de4dab85abbb0957a3e28e1ce658b206e1eefec520ef720d88a43a269` |
| Protected sensor control client/service | `sha256:929cb2eae340e3f0977e7e26f62d0e75c972db3f4d84777ac4edcb7c3df026a6` |
| Process correlation decoder | `sha256:c15d19451927e54af2c3e10e49bad74430eccd2ff4fb96a80e26ead05fb9ca6c` |
| Typed process evidence decoder | `sha256:837e5341ce4d8da647c772d22e5a64dfd438528e1f6cb3410f3bc53a1b287488` |
| Cargo lock | `sha256:0635890ecb3d8b03c683983b3799e2a8fd6aa6252eb914b6e0cc227804f85b93` |

## Remaining integration gaps

The next production collector must still reconcile the supervisor-bound terminal with the
cgroup-filtered BPF lifecycle exit, while treating either missing source as incomplete telemetry.
The current BPF record does not retain the tracepoint `exit_code`; adding it would provide an
additional independent consistency check.

Two other process bindings were open at this checkpoint:

1. The initial blocked leader is forked before it is placed into the package cgroup, so the
   cgroup-filtered BPF program cannot observe that first fork. The service must create a narrowly
   typed supervisor-bound leader-start observation without calling it BPF evidence.
2. The BPF exec event deliberately carries no raw argv or path. The protected service still needs
   to bind the exact expected executable digest, argv digest, and argv count from the fixed launch
   contract without accepting package-controlled strings.

The subsequent
[launch-binding checkpoint](artifact-native-linux-vz-package-sensor-launch-binding-checkpoint-2026-07-14.md)
closes those protocol and typed-evidence bindings. It does not instantiate the production
collector or turn the contract-derived launch identity into an independent runtime measurement.

The production root collector, file/fanotify and post-run diff stream, `connect`/`sendto` physical
qualification and host-frame correlation, signed `EvidenceEnvelope`, complete runtime, inert
package scenarios, benign controls, known-malware regression, and held-out gates remain open.
