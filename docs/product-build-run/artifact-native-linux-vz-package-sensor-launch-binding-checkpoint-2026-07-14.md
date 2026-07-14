# Artifact-Native Linux VZ Package-Sensor Launch-Binding Checkpoint

Date: 2026-07-14

Status: supervisor-bound leader parent and redacted launch identity carried through protected sensor
control and typed evidence

## Outcome

The protected package-process path now closes the two remaining launch-binding gaps identified by
the process-correlator and terminal-binding checkpoints.

First, the receiving root sensor service independently binds the blocked leader to the verified
root runner. The service obtains the runner PID from the root-only Unix channel's peer credentials,
then requires all of the following before it acknowledges the leader and permits release:

- the held cgroup-v2 descriptor contains exactly the claimed leader PID;
- `/proc/<leader>/cgroup` names the exact action cgroup;
- all four real/effective/saved/filesystem UID and GID values in `/proc/<leader>/status` are root;
  and
- the leader's kernel-reported parent PID is the verified root-runner peer PID.

That parent PID is carried through leader-control v2 and process-correlation v3. Typed process
evidence requires the synthetic supervisor-bound leader `fork` observation to name that parent as
its actor. This observation is deliberately not represented as BPF evidence: the initial leader is
forked before the supervisor places it in the package cgroup, so a cgroup-filtered BPF program
cannot observe that fork.

Second, the launch contract now derives one redacted launch identity containing only:

- the exact expected executable SHA-256 already bound by the measured launch contract;
- SHA-256 of the canonical JSON argv array; and
- the exact argv item count.

Arm-control v2, the root collector context, process-correlation v3, and the typed leader `exec`
event must all agree on those values. The control and evidence bindings contain no raw executable
path and no raw argv. Empty digests, zero or excessive counts, contract rebinding, parent rebinding,
executable rebinding, argv rebinding, and count rebinding fail closed.

This closes the protocol and typed-evidence binding for the expected launch. It does **not** claim
that the executable or argv digest was independently measured by a production runtime collector.
That collector does not exist yet; it must derive the enrichment only from the already verified
fixed launch contract while independently consuming the kernel event stream. The July
malicious-package score remains **7/11 (63.6%)**.

## Safety boundary

No package or malware code ran. This checkpoint used only Rust unit tests, native compilation, and
Linux/aarch64 cross-compilation. It did not boot a VM or access restricted evidence.

Real malware may run only on the approved cloud Mac and only inside a fresh disposable Linux VZ
guest under the separate approved lab workflow. It must never run in this workspace, on the Mac
host itself, or in Docker. Sync-back, live C2, and live second-stage retrieval remain forbidden.

## Trust boundary

The parent binding has two independent sources:

1. the supervisor records its own PID immediately before the exact `fork`; and
2. the sensor service obtains the runner PID from `SO_PEERCRED` and compares it with the leader's
   kernel-reported `PPid` while the child is still blocked before release.

Process-correlation v3 must match the supervisor-derived parent and closed launch identity. The
typed process decoder then requires the leader fork actor, leader parent, executable digest, argv
digest, and argv count to match the correlation record exactly. Correlation or typed evidence that
substitutes another parent or launch identity is verdict-ineligible.

The executable/argv binding is intentionally an expected-identity binding, not a second
measurement. The future collector must not accept package-controlled paths or strings to populate
it. Independent executable assurance continues to come from the supervisor's retained-descriptor
measurement and pre-exec remeasurement path.

## Protocol changes

- Arm request/ack v2 adds the expected executable digest, canonical argv digest, and argv count.
- Leader request/ack v2 binds the service-verified parent PID.
- Process-correlation v3 binds parent PID plus the three launch-identity fields alongside the
  previously added exact terminal result.
- The old v1/v2 schema identifiers remain declared for provenance, while active decoding accepts
  only arm-v2, leader-v2, finish-v2, and correlation-v3 records.
- Debug output for the launch contract and launch identity remains digest-only and does not expose
  raw argv or the package path.

## Validation

- Package-sensor Rust library suite: 180 passed.
- Native package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64-musl package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Formatting and `git diff --check`: passed.
- Exact contract-derived identity and root leader status: accepted.
- Empty/count-invalid identities, wrong parent, non-root credentials, correlation rebinding, typed
  fork-parent rebinding, and typed executable rebinding: rejected.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Launch contract and redacted identity | `sha256:5a0f2f8eef7d5c08b68ec59b1885967fd871cc5f53c2d599ea02ce49e680d7a2` |
| Protected sensor control client/service | `sha256:e57c10254e36556132cdd08db388f4a6b235f5bc3a611b5986fd5fa00a781848` |
| Process correlation decoder | `sha256:42f2903dc69a05900bb906acaff00c0490de08cd3c75d74f3ec214c24ebe1310` |
| Typed process evidence decoder | `sha256:e0ff251ae3d68e73669742263d927bea24d0b4c44143359eba5e36c2c1449253` |
| Root process supervisor | `sha256:e702399ce465ef6972ef99e2308b4eb1e5606137e809ecd2af92d165c4e8d5c6` |
| Cargo lock | `sha256:0635890ecb3d8b03c683983b3799e2a8fd6aa6252eb914b6e0cc227804f85b93` |

## Remaining integration gaps

The next highest-leverage slice is the production root collector that owns the BPF producer,
ring-buffer consumer, fail-closed per-thread correlator, and typed process-stream builder inside
the protected service. It must emit the supervisor-bound leader-start observation without calling
it BPF evidence, enrich the exact leader exec only from the fixed verified contract, and reconcile
the supervisor terminal result with an independently retained BPF `exit_code`. Either missing
source must make coverage incomplete.

After that, the project still needs fanotify/file collection and a post-run filesystem diff,
physical `connect`/`sendto` qualification and host-frame correlation, a signed
`EvidenceEnvelope`, complete runtime integration, inert npm/wheel/sdist scenarios, benign controls,
known-malware regression, and held-out gates. Malware regression remains cloud-Mac-only inside
fresh disposable Linux VZ guests.
