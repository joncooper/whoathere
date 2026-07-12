# Artifact-Native Linux VZ File-Telemetry Checkpoint

Date: 2026-07-12

Status: one measured physical Linux VZ backend completed both `fork_exec_exit` and
`protected_open_read_write_rename_delete` with separately signed guest and host evidence; the
backend remains `candidate_unqualified` with 36 of 38 physical cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [First Complete Conformance-Case Checkpoint](artifact-native-linux-vz-first-complete-conformance-case-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The single measured root-owned sensor and single measured inert runner now implement two closed
run-spec cases. The file case runs only the repository-owned fixture as UID/GID 65534 and proves:

- fanotify content-permission observation and five explicit allow responses for file access;
- open, read, and close-after-write observation without exporting raw paths;
- at least one mmap syscall from the same package cgroup and fixture PID through a protected raw
  tracepoint BPF program;
- a write to a fake user-startup file under the disposable fixture tree;
- protected post-run diffs for write, rename, delete, and fake-persistence changes;
- two sensor heartbeats, zero reported drops, complete descendant teardown, and no truncation; and
- denial of package-UID reads and writes against the root-only sensor executable.

The eight-event canonical guest payload contains only event classes, PID, cgroup ID, sequence, and
bounded observation-record timestamps. Those timestamps establish canonical evidence order; they
are not claimed as native per-operation kernel timestamps. Fanotify and BPF retain their independent
kernel provenance, while rename/delete and persistence outcomes are corroborated by the protected
filesystem diff. The mmap correlation is PID/cgroup plus the closed measured fixture action; the
current BPF record does not identify a file descriptor or pathname.

Swift derived the guest claims from that payload, verified the guest signature, independently
derived zero-frame host lifecycle claims, verified the host signature, and accepted the complete
case. Rust retrieved the inert serial and receipt bytes, independently decoded both evidence
payloads, rederived the claims, verified both signatures, and reproduced these bindings:

| Binding or observation | File case |
| --- | --- |
| Backend identity | `sha256:30f7967c30678d49b4b98d1ceca36a31ea23ed3e7da2cbc953ee1cb6668abce5` |
| Signed host helper | `sha256:3d829bbf8055d481d817a193db3752454bd3ad82889f53bbdea07b0658dae0bb` |
| Signed initramfs | `sha256:f41650da94ddca69b3e1d15c270fcfb34c89b170599fcbe477679765a300fc75` |
| Measured guest signer | `sha256:33d635af7c390147e0a696929b1624334d7abb2bb61dd64c6a7c4055b1f2d247` |
| Measured sensor | `sha256:811056ada6e7244a8094905d6814410e81e7e5a1d0c1367fa550c0216b2ba049` |
| Measured inert runner | `sha256:83f7da435d793a3fa9497c57cdbeb427b953894c2b94f4b21fb320c59887a3d9` |
| Challenge | `sha256:811fdf7b8734afcea33150fc279a347232e385b92e3e21d1f419b791164a6b28` |
| Run spec | `sha256:3d73676c3cf4758648d5037956b1b6cceb688dfd5c5290fce321741dbef796c7` |
| Guest file evidence | `sha256:1732beef73c3a33d2815f66efc215ab67a6b7a5f7a3817256001cfff41b172cb` |
| Guest receipt | `sha256:c0124b1e294036f8eba07c0e67a903c4efede69e64558ed3705d9cc6ca81f6a5` |
| Host evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:68e6c5ce9cbcd4a4c17f8e8833499fa1a292fe72e174b18bed2c979ddd0162b6` |
| Raw/external frames | `0` / `0` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Because changing the sensor changes the backend identity, `fork_exec_exit` was rerun rather than
reusing its older receipt. The exact same identity above independently passed the process case with
challenge `sha256:b6e85867534c366c4ec21731a27e17cb557125d56c69681a256101d88de6bf6f`,
run spec `sha256:de87afe3300f09c88f2e2d093ace6297a1729c6fc610e9202953ef85a9275a49`,
guest evidence `sha256:1d2e3f4497216a50fc87d619a30b434e7a74af823724e85948bd5d7fd41c0a12`,
guest receipt `sha256:50fd9ffc4de103a006714a04aea1b212bf42308d0ac60ff0cf851606a04310a8`,
and host receipt `sha256:0e051f59ab7f90b7653eafc8f59901e08becc98dd442107380a19add5dc5636c`.

## Fail-closed engineering findings

Three physical draft attempts produced no receipts and exposed concrete integration faults: an
uninitialized BPF return register rejected by the kernel verifier, an invalid fanotify mask/mark
combination, and a root-only `/run` parent that prevented UID 65534 from reaching its intentionally
owned fixture tree. The final sensor initializes all BPF exit paths, assigns fanotify and protected
diff responsibilities separately, and changes `/run` to execute-only traversal only for the fixture
window before restoring mode `0700` during cleanup.

## Validation and boundary

Two clean final signed-image builds were recursively byte-identical and both passed the independent
signed-image verifier. Rust focused tests, Swift's 107 tests, cross-compiled C with warnings denied,
and independent physical receipt verification passed. Full workspace gates are recorded with the
commit containing this checkpoint.

This is protected telemetry qualification work, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. The file fixture uses only inert canary bytes and a fake
startup path inside a one-boot, diskless VM. The backend is now 2 of 38 on one exact identity; it is
not qualified and cannot issue package-execution authority. The next gate is the distinct
`mmap_access` case on this identity, followed by remaining process, network, fault, teardown,
platform, and isolation cases.
