# Artifact-Native Linux VZ Package Root Process-Evidence Checkpoint

Date: 2026-07-14

Status: canonical root process-observation payload implemented, integrated into the process-only
collector adapter, and physically qualified with an inert fixture on the approved cloud Mac

## Outcome

The concrete root process collector can now turn its completed kernel-correlated stream into one
canonical payload with schema
`whoathere.linux_vz_package_root_process_evidence.v1`. A separate strict decoder accepts the
payload only when the caller supplies the exact expected action binding. The decoded type exposes
the observations, runtime identities, loss/drain accounting, and reconciled leader lifecycle so a
later supervisor or evidence-envelope consumer does not have to trust untyped JSON.

This is deliberately a lower-level process-observation payload, not a replacement for the existing
three-sensor package evidence contract. The process-only root-service adapter now creates and
retains it after a successful collection, then still returns no finish status. The adapter reports
file and network sensors unavailable, so the enclosing service refuses arm and cannot release a
package. File telemetry, network telemetry, protected payload transport, composite correlation,
authenticated envelopes, runtime scenarios, benign controls, and malicious regression remain
open. The July malicious-package score remains **7/11 (63.6%)**.

## Exact binding

The expected binding is constructed from protected state rather than payload claims. It includes:

- sensor-session challenge digest;
- launch-contract and process-plan digests;
- action index and the exact `whoathere-package-action-{index}` cgroup name;
- kernel cgroup id;
- root-runner and leader PIDs;
- contract-derived expected executable digest, canonical argv digest, and argv count;
- exact supervisor start/end monotonic times;
- raw supervisor wait status plus one valid exited/status or signaled/signal terminal; and
- fixed package UID/GID 65534.

Empty or aliased digests, unsafe cgroup names, invalid PIDs, invalid argv counts, stale action
bindings, and terminal rebinding fail closed. The executable and argv values are explicitly the
expected identity from the fixed launch contract; this slice does not pretend the lifecycle
tracepoint independently hashes the runtime executable path.

## Canonical observation contract

The payload retains two observation forms:

- lifecycle: fork, exec, or exit with exact source sequence, timestamp, cgroup, PID/TGID,
  parent/subject PID, CPU, and raw kernel wait status where required; and
- selected syscall: exact syscall name, entry and exit source sequences/timestamps, PID/TGID,
  entry/exit CPUs, signed result, and a domain-separated SHA-256 of the six kernel argument words.

Only `setuid`, `setgid`, and `setgroups` expose argument zero as a safe normalized integer. Raw
argument vectors, pointer values, exec paths, and argv strings are structurally forbidden. Network
destinations and file paths therefore still require their dedicated sensors.

The decoder reconstructs the underlying source events from lifecycle records plus both halves of
every syscall observation, sorts them by source sequence, and requires exactly `1..N` with strictly
increasing kernel timestamps. This represents overlapping pairs from interleaved threads without
requiring adjacent enter/exit records, while still rejecting gaps, duplicates, reordered
observations, incomplete pairs, and timestamp rollback. An explicit regression test covers two
overlapping syscall pairs.

## Runtime and coverage identity

The payload also requires and exposes:

- runtime BTF SHA-256 and the bounded `task_struct.exit_code` byte offset;
- the exact five distinct tracepoint-format digests;
- a sorted unique online-CPU set and an attachment CPU contained in that set;
- zero producer drops and zero consumer discards;
- complete, non-truncated, continuously drained coverage;
- active poll/nonempty-poll counts;
- source records consumed before finish and during finish, whose sum equals the source count;
- bounded maximum drain-batch size;
- exactly one reconciled leader exit;
- the exact leader exec count and first-exec/exit timestamps; and
- equal raw kernel and supervisor wait statuses with descendant teardown complete.

Noncanonical JSON, unknown fields, raw-capture upgrades, runtime-identity substitution to an empty
or duplicate digest, CPU mismatch, accounting disagreement, source loss, and lifecycle mismatch all
fail closed with stable reason codes.

## Physical qualification

No package and no malware sample ran. The final physical run used the existing purpose-built inert
credential/exec/loader fixture in one fresh disposable Linux VZ guest. The guest was diskless and
had no directory share, external route, or sync-back path. The strict schema-v8 Mac verifier exited
`0` with canonical `status: "ok"`.

The final run proved:

- 14 kernel source records became eight typed observations;
- the canonical process payload was 5,456 bytes with SHA-256
  `1d87062634049b82a0ae1bef63322ad628d853af264ae23dd51400e34b2033a7`;
- all 14 records were consumed before finish with zero finish-drain records;
- 40 active drain polls, two nonempty polls, and maximum batch size 13;
- exact leader exec count one and equal kernel/supervisor wait status zero;
- CPU 1 event delivery from the CPU 0 tracepoint-wide attachment;
- zero pre-release events, producer drops, or consumer discards;
- the existing injected eight-event limit still produced a first-fault marker after 1,348
  microseconds, descriptor-relative cgroup kill, and exact `SIGKILL` termination of the second
  inert fixture;
- zero host raw frames and stable kernel/initramfs identities; and
- a stopped VM before acceptance.

The outer canonical schema-v8 qualification evidence was 2,764 bytes with SHA-256
`0faa239ab889142d4f98c66ef6280ef14a0f56567c15bf34e5a48180b29a0c0a`.
The retained sanitized serial transcript was 3,612 bytes with SHA-256
`52de958a4d5c8cd7b5c354f9e20db8962e6b50e4d2ae7e55cf89ff34e1fd7ee9`.

Exact final inputs were:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 10,148,959 | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Guest init | 1,750 | `6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Static canonical-evidence inert probe | 1,120,784 | `c7e5d891650567652ba1c722a630ffb6a61927cf6d0e4c1677d4382870dccc43` |
| Static inert fixture | 371,736 | `09933b6efc035a0d6c43ca3cf63e76e5d49ada432c7418e7e929b60c9d613b7e` |
| Canonical overlay CPIO | 1,495,040 | `e44b10cd0310a3b3bed7c01d3e17d8fb62b1d6de1cdf44d77aa6b4310503975a` |
| Deterministic gzip overlay | 757,168 | `eb53868ab6ff6ad84845be0d633542dd22e2c6a0120965d95583ed35edde8de1` |
| Combined qualification initramfs | 10,906,127 | `f8a4bcd3e98d39a9360b675b8bf0f0392e1619b61b332ffe5d1f9af0059a326c` |
| Strict entitled Mac verifier | 2,844,080 | `647c8fe3e1a79d40562ab4e7d0ef094794773fabda83ab533984aa9b5328ae9a` |

Two independently generated overlay CPIO and deterministic gzip outputs were byte-identical. The
verifier signature was valid and carried the macOS virtualization entitlement. The remote staging
directory was removed after the sanitized transcript was retained locally under the ignored
`.whoathere/` evidence tree.

## Validation

- Focused canonical-evidence tests: 6 passed, including interleaved syscall pairs and strict
  negative cases.
- Package-sensor Rust library suite: 194 passed on macOS.
- Full Rust workspace test suite, including integration tests and doctests: passed.
- Swift helper suite: 200 passed.
- Native package-wide Clippy with warnings denied: passed.
- Linux/aarch64-musl package-wide Clippy with warnings denied: passed.
- Static aarch64-musl release probe and fixture build through `cargo zigbuild`: passed.
- Release Mac verifier build, ad-hoc virtualization-entitlement signing, and strict signature
  verification: passed.
- Two deterministic overlay builds: byte-identical.
- Exact normal plus injected-fault physical inert qualification: passed.
- Formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Canonical root process evidence and decoder | `4cf6484a42d9a2e9cf47c2e69b1cca14ad565423761b4d791abcb003ef47d671` |
| Root sensor control and process adapter | `72a7eb9d83354e5ab1296e626a4a8ff444f16cc3592c210573e63fd65031d62a` |
| Inert physical qualification probe | `89d564d34d029020d26d0983f2d12740f3004009e3bc4eda18f4cf8f151ddeb9` |
| Strict Swift schema-v8 evidence decoder | `ae7bc552f238545c2bfe3260e3f49dfb4b0584a39158c5e086bff5ea213f3fbb` |
| Strict Mac physical verifier entrypoint | `2a8bee069f289ceb29e2ae909178078e384fb0ae62b37a528eb6f1d8dc96cec7` |

## Claim boundary and next step

This checkpoint proves canonical, typed process-observation evidence from the real root collector
under an inert physical workload. It does not prove arbitrary package safety, file or network
coverage, live exfiltration detection, a signed composite package receipt, low false positives, or
improved malicious-sample detection.

The next implementation slice is a concrete protected file collector that can correlate path-class
tokens and a complete post-action filesystem diff to this same action/global sequence without
exposing raw paths. The process payload must then cross the protected control protocol and join
file/network payloads under one authenticated composite envelope before package release can be
considered.
