# Artifact-Native Linux VZ Package Root File-Evidence Checkpoint

Date: 2026-07-14

Status: concrete root file collector, canonical file-evidence payload, process/file composition, and
an inert physical cloud-Mac qualification are complete; network evidence and package release remain
unavailable

## Outcome

WhoaThere now has a concrete Linux root file collector for one package action. It continuously
drains fanotify permission and close-write events, correlates actors to the protected action cgroup,
classifies and tokenizes paths without retaining raw path strings, and computes an independently
measured before/after workspace diff after the action cgroup is empty. It encodes those results as
canonical schema `whoathere.linux_vz_package_root_file_evidence.v1`, bound to the same session,
launch contract, process plan, action, cgroup, runner, leader, and terminal state as process
evidence.

The root sensor-control service now composes the concrete process and file collectors. Both must arm
and finish successfully, both canonical payloads are retained, and a fault from either collector
propagates through the existing root-runner fault path. The service still reports network evidence
unavailable, so it cannot acknowledge arm or release a package. This checkpoint therefore improves
the evidence substrate but does not improve the July malicious-package score, which remains
**7/11 (63.6%)**.

## Collector boundary

The collector opens fanotify as root with `FAN_CLASS_CONTENT`, nonblocking and close-on-exec flags.
It requires five marks before launch:

- mount marks for `/`, `/sys`, `/dev`, and `/run`;
- a descriptor-relative mount mark for the exact `/run/whoathere` workspace; and
- `FAN_OPEN_PERM`, `FAN_ACCESS_PERM`, `FAN_OPEN_EXEC_PERM`, and `FAN_CLOSE_WRITE` coverage on each
  mark.

An explicit physical capability diagnostic tested `/`, `/proc`, `/sys`, `/dev`, `/run`, and the
workspace with both the complete and reduced masks. `/proc` rejected mount and inode marks with
Linux `EINVAL` while the other five accepted the complete mask. The production schema therefore
states both facts instead of silently widening the claim:

- `declared_scope_complete: true` for the five required marks; and
- `global_mount_coverage_complete: false`, with `proc_mount` in the exact unobserved-mount list.

Access to `/proc` by the package is not verdict-grade file evidence at this checkpoint. A later
collector must close that gap or preserve it in the composite evidence and policy.

The worker polls every five milliseconds while the leader is active. It refuses a pre-release
target event, fanotify overflow, malformed metadata, response failure, source-event overflow,
workspace identity change, snapshot race, or snapshot/byte limit. After a collector fault it keeps
draining permission events in deny mode while the root runner tears down the cgroup.

For each event, the collector verifies current membership through the already-open action-cgroup
descriptor and binds the actor PID to its `/proc/{pid}/stat` start time to resist PID reuse. A
tracked actor that leaves the cgroup while still alive fails closed. Events from unrelated actors
are allowed but counted separately and cannot become package evidence. Protected-sensor paths are
denied. Every permission decision is counted, and any queue overflow makes coverage incomplete and
the collection unusable.

## Redacted event and diff evidence

Verdict-grade events retain only:

- event kind: open, read, write, or open-exec;
- closed path class and absolute or workspace-relative namespace;
- observed or denied outcome;
- contiguous source sequence and monotonic timestamp;
- actor PID and expected cgroup id; and
- a session-challenge-, namespace-, class-, and path-bound SHA-256 token.

Raw paths are zeroized after classification and are structurally absent from canonical evidence.
Sensitive credential paths are classified without exposing their contents. Raw fanotify file
descriptors remain collector-local.

The workspace baseline and final snapshots are descriptor-relative and bounded to 131,072 entries
and 1 GiB of regular-file content. They record entry type, ownership, mode, device/inode identity,
link count, byte length, content or symlink-target digest, and a domain-separated fingerprint. The
diff distinguishes create, modify, delete, and inode-bound rename. Canonical evidence contains only
path tokens, path classes, entry kinds, content/metadata change booleans, and digest commitments to
the baseline, final snapshot, and complete diff.

The strict decoder rejects unknown fields, noncanonical JSON, binding changes, raw-path upgrades,
duplicate or gapped event sequences, timestamp rollback, invalid snapshot counts, incomplete mark
coverage, nonzero overflow, unaccounted permission decisions, invalid change shapes, aliased
digests, and any diff completed before process exit.

## Physical qualification

No package and no malware sample ran. The final run used the purpose-built inert static fixture in
one fresh diskless Linux VZ guest on the approved cloud Mac. The VM had two vCPUs, no root disk, no
directory share, one host raw-frame sinkhole with no external route, and no sync-back path. The
strict signed Mac schema-v10 verifier exited `0` with `status: "ok"` and
`evidence_valid: true`.

The final run proved:

- five required fanotify marks and an explicit unobserved `proc_mount`;
- 12 cgroup-correlated file source events, 11 permission responses, zero denials, zero ignored
  non-cgroup events, and zero fanotify overflows;
- 47 active drain polls, six nonempty polls, and a maximum batch of four events;
- one inode-bound workspace rename whose content and metadata both changed;
- a 6,372-byte canonical root file-evidence payload with SHA-256
  `5b7673732cce2c5f64c5dc8b4acecc77fc0134e69b0d7ce1ad614c7c941a6c3c`;
- baseline, final-snapshot, and workspace-diff digests of
  `713603e97bd6dfec453fd47cf4d8b22f9e01c07234eb06db29320b6514109c0d`,
  `4fc4805e73beb04163a876de7eee672b4e8f9ce18d55579c4a8bbf8d47c6f6be`, and
  `b8c460c51285457e80b916cfbf45a5c2310180f164de3f91298ffc568359257f`;
- the composed process collector still produced 14 source events, eight observations, zero loss,
  and a 5,455-byte canonical payload with SHA-256
  `da7a7d84649ac64faa2f6a299862d41c90874759b3a41ff0e0a3c9fba3909e01`;
- the injected source-limit fault still signaled after 1,115 microseconds, killed the fault cgroup,
  and reaped the second inert fixture with exact `SIGKILL` status;
- outer canonical schema-v10 evidence was 4,271 bytes with SHA-256
  `e95062763388554746e64efa91b178569fb93e9788b5c3e5962146ca812283fb`;
- zero host raw frames, stable kernel/initramfs identities, and a stopped VM before acceptance; and
- `package_execution: false`, `malware_execution: false`, and `sync_back: false`.

The retained remote sanitized serial transcript is 5,119 bytes with SHA-256
`f46e0e2633dcd95637b08793bfc4efaa60d7779b2e242828497f54861e289607`.

Exact final inputs were:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 12,472,222 | `9e6519ef2034469a1fbb298f4a1fb7653576eb7287600b1d9b0c75c6a2d0ae45` |
| Guest init | 2,205 | `8e4b7a709ae061f88cedaf45db55b3a9f7e94730aa4a966ed3bb5029ec12c709` |
| Static file/process inert probe | 1,473,240 | `c6aebe9d6ad3170a2d2c1f40d52e1a1085e1eb62fa0cc3a69e52c08248b366c2` |
| Static inert fixture | 380,248 | `f1c5947782db83d567911786340507a0df7930ed99e5872e0ee1ade65493c139` |
| Canonical overlay CPIO | 1,856,512 | `dbc2b690809517f180584877d6928767b164e010790f57c6639a114fb788d989` |
| Deterministic gzip overlay | 911,442 | `2bcde113387c069439f53cd54f782b9dc16c346b5cb9eec14c93e94e7d3955a9` |
| Combined qualification initramfs | 13,383,664 | `11eb246f1fac35cf6a7269238a6750c3c15c67138e256c0aea801df62da6f8eb` |
| Strict entitled Mac verifier | 2,850,048 | `38c8d00ae07dddf5ec6145e07cc27d80024f46bae3ee458abd48435aebdd9472` |

The verifier passed strict code-signature validation and carried the macOS virtualization
entitlement. Its first run correctly rejected semantically valid but noncanonical outer JSON after
the new fanotify fields changed struct insertion order. The guest now uses the canonical JSON
serializer at the boundary; the unchanged strict host decoder accepted the rebuilt evidence. This
is a useful fail-closed result, not a relaxed verifier.

## Validation

- Canonical root file-evidence tests: 3 passed, including exact round-trip and strict coverage,
  unknown-field, and noncanonical negative cases.
- `whoathere-macos-vm` Rust library suite: 202 passed.
- Swift helper suite: 200 passed.
- Native package-wide Clippy with warnings denied: passed.
- Linux/aarch64-musl package-wide Clippy with warnings denied: passed.
- Static aarch64-musl release probe and fixture build through `cargo zigbuild`: passed.
- Strict code-signature and virtualization-entitlement verification: passed.
- Exact inert physical qualification, including injected process-fault behavior: passed.
- Rust formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Concrete root file collector and diff | `66f62ac6e8650157c0e136379f871675ff8a9a611c17a9a113fd738cfc67d043` |
| Canonical root file evidence and decoder | `5dd6ab08d9f2f77da21e177edc9bc86f93d7be0fedf17890177272d75a801777` |
| Root sensor process/file composition | `0e5b633414acace40e86730514ab8a4f62a91b977c8735c7538fe10772223216` |
| Inert physical qualification probe | `c77a6c16655c70347e022abc73e89115919b2c309543d5ec9b2ebb4ddfe7bf05` |
| Strict Swift schema-v10 evidence decoder | `3121f58ed8c3b74c6bdd8c2b9f7908c75f6051cc92ae17c583d350f0171f69f7` |
| Strict Mac physical verifier entrypoint | `64d0c8545651c3690e11ea2e9a02033f3a6e64f4ec351579199fabd4d18de622` |

## Claim boundary and next step

This checkpoint proves canonical, redacted file evidence for the declared five-mark scope and a
post-action diff for the exact workspace under an inert physical workload. It does not prove global
mount coverage, `/proc` file visibility, network correlation, signed composite package evidence,
arbitrary npm/PyPI safety, low false positives, or improved malicious-sample detection.

The next implementation slice is the protected network collector and host/guest raw-frame
correlation. Process, file, and network payloads must then cross the protected control protocol and
join under one authenticated composite envelope before the runtime can issue package execution
authority or any verdict can affect admission.
