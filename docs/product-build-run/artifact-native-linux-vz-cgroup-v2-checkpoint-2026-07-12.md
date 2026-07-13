# Artifact-Native Linux VZ cgroup-v2 Checkpoint

Date: 2026-07-12

Status: `cgroup_v2` plus the thirty-four earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 3 of 38 cases pending

## Outcome

The second platform-capability gate now proves live cgroup v2 operation rather than relying on a
boot marker or on cgroup use incidental to another fixture. The protected, measured guest signer
requires the cgroup2 superblock magic and exactly one `/sys/fs/cgroup` cgroup2 mount record, reads
the bounded root controller list, and creates a fixed-name temporary domain cgroup.

The signer moves itself into that child through the kernel's `0` self-migration interface, then
independently requires its actual PID in `cgroup.procs` and `populated 1` in `cgroup.events`. It
moves itself back to the root cgroup, requires an empty child plus `populated 0`, removes the child,
and verifies that its path is absent before it signs evidence. This uses only the measured signer;
no package binary or other arbitrary process is executed.

Strict Rust and Swift implementations independently reject an invalid filesystem or mount binding,
empty, duplicate, unsorted, or malformed controller lists, missing membership or population,
incomplete return-to-root or removal, wrong package UID/GID, noncanonical or duplicate evidence,
drops, unhealthy status, truncation, or a non-complete terminal.

| Binding or observation | Final cgroup-v2 case |
| --- | --- |
| Backend identity | `sha256:edf1c27558a519e49a6aa5b284d21ff0bf6c19a70cc1d40b088e515312a96294` |
| Entitled signed host helper | `sha256:6a4a41fdd1e0821f2415c7a0304934908d789ebc361bce13eabc8be9a64a8f92` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:9cdc3f23ab6d8516eb3bf5dd0e7f0852460da96db7333723c015f57794f2a43b` |
| Guest signer | `sha256:735bdc8fd6926966f5e05a6309b88d9dab4ca2e4062c5fc739fc16555f94666e` |
| Protected process sensor | `sha256:1888030009504f9e382f669cab6dcd0f96e7de23c89d9e876b81b20c9290b60a` |
| Fixture child | `sha256:7e7a89c131266f020035f35787e8f052e6901b390deffb433a22ef85cf02c2f7` |
| Signed-image manifest | `sha256:ff121d1ce6431cea87743c81081bb05300bce3d8931b8c93ed91ec48c214d250` |
| cgroup2 filesystem / mount | magic `63677270`; `/sys/fs/cgroup`; `cgroup2` |
| Available controllers | `cpu`, `cpuset`, `dmem`, `hugetlb`, `io`, `memory`, `pids` |
| Membership target | measured guest-signer PID `409` |
| Child lifecycle | created domain; populated; emptied after return-to-root; removed |
| Challenge | `sha256:03ab2609a74a1483a7eedef5b8dbb947f61aa04bda76dbc21dc2cc81886c4f01` |
| Run spec | `sha256:ebc9065255bf3b93902a7ac817247d585fd7d96f645ae7363d35b093060c523c` |
| Request frame | 5,018 bytes; `sha256:c2352ac7fc725a70b851288a9c67f8bdb944f9d8ec309eddaba0e5b6e1c00d9c` |
| Guest cgroup evidence | `sha256:3c324b5e27836fc407bc1f331405d22b0a626c9a296ad72cb56540db84759971` |
| Guest receipt | `sha256:1d231b247f59e09a2f088a62d3c26518bb097ece6f8eb24743394bc8f205c250` |
| Host lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:88169b6458e076783e93ece49b6fc1dcf74a080abf66787ae7486f3e712d4499` |
| Sanitized serial | `sha256:7b8057f84914ecf2807338a060a6c6efb514b23e825350ff1a42180aa2270932` |
| Guest events / guest drops | `5 / 0` |
| Raw frames / host drops | `0 / 0` |
| VM stopped / clone destroyed | `true / true` |
| Execution authority / package execution / sync-back | `false / false / false` |

Two independent local image builds were byte-identical and both passed the signed-image verifier.
All 35 implemented cases then ran physically on the final identity and passed the independent Rust
complete-case verifier. The gitignored inert evidence archive contains 242 files, including all
105 request inputs, and has SHA-256
`7a1a50aaec5e1ae27a2c871b495f2c7210a7b9aa9518e46f8b34bf454ce11b3f`.

The full Rust suite, 181 Swift tests, format and strict Clippy gates, deterministic 38-case fixture
contract, strict static aarch64-musl sensor and fixture builds, and all four repository smoke
harnesses passed before this checkpoint was committed.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, restricted, unknown, or
malware package code ran. The backend cannot issue package-execution authority. The next closed
gate is `fanotify_permission`, followed by `bpf_program_types` and `raw_frame_attachment`.
