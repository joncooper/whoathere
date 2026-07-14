# Artifact-Native Linux VZ Package-Sensor Cross-CPU Coverage Checkpoint

Date: 2026-07-14

Status: tracepoint-wide cross-CPU delivery physically qualified with an inert fixture on the
approved cloud Mac

## Outcome

The package BPF producer's single perf-event attachment on CPU 0 delivered the complete selected
tracepoint stream for a child constrained to CPU 1. The strict final run observed all 14 expected
credential, exec, loader-`mmap`, and exit records on CPU 1, with zero producer drops and zero
decoder discards.

This closes an evidence gap, not a detection gate. Earlier qualification proved that the producer
could capture the exact inert stream, but it did not force the child away from the CPU used to
create the perf event. The new schema-v4 qualification makes those two facts distinct and requires:

- `attachment_cpu = 0` and `attachment_scope = tracepoint_wide`;
- `fixture_cpu = 1`, different from the attachment CPU;
- `observed_event_cpus = [1]` for every one of the 14 records;
- the exact online CPU set `0,1`;
- the existing exact sequence, syscall pairing, BTF-bound kernel exit status, and independent
  `waitpid` status; and
- zero loss, zero host frames, stable input images, and a stopped VM.

The physical result confirms the behavior of this exact pinned two-vCPU backend: the perf event's
CPU argument is the attachment anchor, while the BPF program is registered through the kernel's
tracepoint-wide program array. Attaching the same program again for each CPU is neither necessary
nor the correct model; the earlier physical work already found that the duplicate registration is
rejected with `EEXIST`.

The production root collector is still not instantiated. Fanotify/file evidence, post-run
filesystem diff, package-bound network correlation, signed evidence envelopes, complete runtime
integration, inert npm/wheel/sdist scenarios, benign controls, and malicious regression all remain
open. The July malicious-package score remains **7/11 (63.6%)**.

## Safety boundary

No package and no malware sample ran. The only executed guest payload was the already-qualified,
purpose-built inert fixture. The final run used a fresh disposable Linux VZ guest on the approved
cloud Mac with:

- no external route;
- no root disk or directory share;
- zero host-observed raw frames;
- package execution reported false;
- malware execution reported false;
- sync-back reported false; and
- a stopped VM before the host verifier accepted the result.

Real malware remains cloud-Mac-only and may execute only inside a fresh disposable Linux VZ guest
under the separate restricted-lab workflow. It must never execute in the local workspace, in
Docker, or directly on either Mac host.

## Qualification design

The inert probe now requires at least two online CPUs. After the protected parent forks a stopped
child and places it in the held package cgroup, it uses `sched_setaffinity` to constrain that child
to the last online CPU. On the qualified backend that is CPU 1, while the producer's single
tracepoint perf attachment is created on the first online CPU, CPU 0.

Every decoded kernel record must report the selected fixture CPU. This check covers the six
credential syscall records, the exec record, six loader-`mmap` records, and the raw-tracepoint exit
record. A missing record, a record from another CPU, a changed order, a sequence gap, an unmatched
syscall, a loss counter, or a mismatched kernel/supervisor terminal status fails the probe.

Canonical guest evidence schema v4 adds `fixture_cpu` and `observed_event_cpus` while retaining the
explicit attachment CPU and `tracepoint_wide` scope. The strict Swift decoder accepts only the
exact measured two-CPU topology and cross-CPU relationship. It rejects an attachment rebound to
CPU 1, an event rebound to CPU 0, unsafe execution flags, nonzero loss, noncanonical JSON, duplicate
evidence, changed BTF identity or task-field offset, and changed terminal status.

## Physical qualification

The final strict host verifier exited `0` with canonical `status: "ok"`. It bound:

- tracepoint perf attachment CPU `0`;
- inert fixture CPU `1`;
- observed event CPUs `[1]`;
- source sequence `1..14` and event count `14`;
- cgroup ID `21` and fixture PID `388`;
- runtime BTF SHA-256
  `d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb`;
- `task_struct.exit_code` byte offset `1964`;
- kernel and independent `waitpid` raw wait status `0`;
- zero dropped and discarded records;
- zero host raw frames; and
- a fully stopped disposable VM.

The canonical guest evidence was 1,577 bytes with SHA-256
`b627061f1e085873f401c22c73acc69c1e5a8bf322df756da1ba8c8ab5e5ac21`. The sanitized serial
transcript was 2,425 bytes with SHA-256
`a01fbe8a56ac11c48828af72b38ece289f6cdd23a7b1a2a0264ab7f74012be99`.

Exact final inputs were:

| Component | SHA-256 |
| --- | --- |
| Pinned Linux kernel | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Guest init | `6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Static cross-CPU inert probe | `3b962ff4595deb08f9345ae1185a6e4a82a07e77e7fd5e67978d8e60ed221678` |
| Previously qualified inert fixture | `c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6` |
| Canonical overlay CPIO | `3bb30d6bed82fe3e2fe0f51ce4d9e8f076e9dc790e2f9c5afcf603231a1243bd` |
| Deterministic gzip overlay | `175e3e9b5596cef8c63316c136c46b7ae74c3a339b01e69f21ca4c6fcdec0406` |
| Combined qualification initramfs | `ee802af1afefaa819d421a06beeb394344974cf72efd566751f1d6bd8169e790` |
| Strict entitled Mac verifier | `c28e86675287684c7ccc5fe04aa4ae578879bd18fdf143dba0ec88fd2f7f7404` |

The overlay CPIO was 1,028,096 bytes, its deterministic gzip was 536,002 bytes, the combined
initramfs was 10,684,961 bytes, the static probe was 654,080 bytes, and the signed verifier was
2,819,392 bytes.

## Validation

- Package-sensor Rust library suite: 184 passed.
- Swift helper suite: 200 passed.
- Native package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64-musl package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Static aarch64-musl release probe build through `cargo zigbuild`: passed.
- Release Mac verifier build, ad-hoc virtualization-entitlement signing, and strict signature
  verification: passed.
- Exact cross-CPU physical inert qualification: passed.
- Formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| BPF producer and attachment path | `b76839c1c1519a3852419b9d744033b772ebabf2876f0bec9bfbfa0257d0a41b` |
| Cross-CPU inert probe | `91d63e69194e01ce3069399076fe12e2288e3fd279c08322036ccb745b47b1fa` |
| Strict Swift evidence decoder | `c7b4c16d37dfda028868c44c1610474ec5aa5fae067e5db9465fd6f5ad62b7ff` |
| Strict Mac verifier | `8e0ccfa3ee90bc2e7864ac166a809b90b941fd00a878520dfbbbd37d76acd028` |
| Swift decoder tests | `1366d8b6a75b0444c6d24a8981250a210c466ecd1aae04fae9621672d83a481a` |

## Next step

Return to the production root collector. It must own the already-qualified BPF producer and ring
consumer, feed the fail-closed process correlator, reconcile kernel and supervisor terminal status,
and mark coverage incomplete on either sensor loss or any unfinished syscall pair. This checkpoint
removes cross-CPU tracepoint delivery as an unresolved premise; it does not remove the collector,
file, network, envelope, runtime, benign, or malicious gates.
