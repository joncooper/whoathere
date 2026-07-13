# Artifact-Native Linux VZ BPF Program-Types Checkpoint

Date: 2026-07-13

Status: `bpf_program_types` plus the thirty-six earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 1 of 38 cases pending

## Outcome

The fourth platform-capability gate proves that the pinned guest kernel can load, attach, and run
the two BPF program types required by the current protected telemetry design. This is stronger than
accepting a successful `bpf()` load syscall: the measured root sensor queries each live program's
kernel-assigned type and ID, exercises its attachment, and requires behavior that only the attached
program can produce.

For `BPF_PROG_TYPE_RAW_TRACEPOINT`, the sensor creates a measured `BPF_MAP_TYPE_ARRAY`, loads a
cgroup-filtered program, attaches it to `sys_enter` with `BPF_RAW_TRACEPOINT_OPEN`, and runs the
fixed UID/GID 65534 inert fixture. The fixture makes exactly one targeted `getpid` syscall. The
sensor requires exactly one map observation bound to that actor PID and measured cgroup, with a
nonzero timestamp and the live program ID returned by `BPF_OBJ_GET_INFO_BY_FD`.

For `BPF_PROG_TYPE_SOCKET_FILTER`, the sensor loads a distinct program, confirms its live type and
ID through the same kernel interface, and attaches it to a private Unix datagram socket with
`SO_ATTACH_BPF`. The fixture sends the fixed eight-byte inert marker; the filter returns four, and
the sensor accepts only the exact four-byte prefix. An unattached, rejected, or nonexecuting filter
therefore cannot satisfy the case.

The sensor reaps the child, closes the raw-tracepoint link, both program descriptors, the map, and
both socket descriptors, leaves the fixture cgroup, and removes it before emitting complete
evidence. Strict Rust and Swift decoders independently bind the exact program and attachment types,
actor and cgroup identity, distinct nonzero runtime program IDs, one raw-tracepoint observation,
the 8-to-4-byte socket result, healthy zero-drop evidence, and complete resource and descendant
teardown.

| Binding or observation | Final BPF program-types case |
| --- | --- |
| Backend identity | `sha256:1e6c51d06616fe2800091c36a48ff1df0aecadeee4d05e0998acee96b50d336a` |
| Entitled signed host helper | `sha256:9501f44f079698daf856c86af214812d85be0a90f7544456daad6d2cacb5ce82` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:675fff5a03ac0bba9767532a3442743d1889eee738ca65e91191127d330e7dfe` |
| Guest signer | `sha256:5ddb4f353ed097f54471b3ab7039e1d35bb88e4522ef26b0378dd2d98001bfde` |
| Protected sensor | `sha256:b7e0bf7806b8062942e130326dfcfbe32c052729d922e6479d1061e542f04d31` |
| Fixture child | `sha256:316782b9012082d329a186a89faa1cdbf2f42482f89acd313548e3296c129676` |
| Process-fixture bundle | `sha256:064a5a7e82800368a286a4dc44bc8ed8b3ce0c414fd80d7018ddcece9c220c79` |
| Signed-image manifest | `sha256:01f1eac8a281a70e86b363cf4a55724be1e17b00c8a8411b40bfda8ebe48525f` |
| Observation map | `BPF_MAP_TYPE_ARRAY` |
| Raw-tracepoint program / attachment | `BPF_PROG_TYPE_RAW_TRACEPOINT`; `BPF_RAW_TRACEPOINT_OPEN`; `sys_enter` |
| Raw-tracepoint actor / cgroup / observations | PID `411`; cgroup ID `21`; exactly `1` |
| Raw-tracepoint runtime program ID | `3` |
| Socket-filter program / attachment | `BPF_PROG_TYPE_SOCKET_FILTER`; `SO_ATTACH_BPF` |
| Socket-filter runtime program ID | `4` |
| Socket-filter input / accepted output | `8 / 4` bytes; exact `WHOA` prefix |
| Challenge | `sha256:854a166759f529acef69464170d92c05302cc0186f4b1a469ba3f764749d6580` |
| Run spec | `sha256:d1b9c5212f56bc0e408ecbbcbd31e62348c88628386a3a408d6ac8cb0e1a26d4` |
| Request frame | 5,048 bytes; `sha256:23814f55a9fa091146ab71f1f99dad7c24958a9530b56856066468cd140f0e14` |
| Guest BPF evidence | `sha256:df2ee085bbc240b7490ac34eb5e1f04f669c0db8d4895748cd038f02164e968f` |
| Guest receipt | `sha256:ccd3eb6aa7c24c436868431fd8a11d243a485e49b685a5a317862aff40670b99` |
| Host lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:33720893ff502b6a35f3e89a1d34e4162ca73048f4edd59006b9489b701e13fe` |
| Sanitized serial | `sha256:0bef017361331f118adf7d7430633e620fb00acfa9365c5312adadad1a5c1708` |
| Guest events / guest drops | `2 / 0` |
| Raw frames / host drops | `0 / 0` |
| Resource / descendant teardown | `true / true` |
| VM stopped / clone destroyed | `true / true` |
| Execution authority / package execution / sync-back | `false / false / false` |

Two independent local image builds were byte-identical and both passed the signed-image verifier.
All 37 implemented cases then ran physically on the final identity and passed the independent Rust
complete-case verifier. The gitignored inert evidence archive contains 330 files, including all
111 request inputs, and has SHA-256
`6e43a8121bb9939b41b18cbf636891429e190029b684a1ce896a73bd59da6077`.

The full Rust suite, 183 Swift tests, format and strict Clippy gates, deterministic 38-case fixture
contract, strict static aarch64-musl sensor and fixture builds, and all four repository smoke
harnesses passed before this checkpoint was committed.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, restricted, unknown, or
malware package code ran. The backend cannot issue package-execution authority. The final closed
platform-capability gate is `raw_frame_attachment`.
