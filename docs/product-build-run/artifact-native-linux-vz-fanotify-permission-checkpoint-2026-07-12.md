# Artifact-Native Linux VZ Fanotify-Permission Checkpoint

Date: 2026-07-12

Status: `fanotify_permission` plus the thirty-five earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 2 of 38 cases pending

## Outcome

The third platform-capability gate proves real fanotify permission-event handling rather than only
proving that `fanotify_init` exists. The measured root sensor creates a `FAN_CLASS_CONTENT` group,
adds a mount-scoped mark carrying `FAN_OPEN_PERM`, `FAN_ACCESS_PERM`, and `FAN_CLOSE_WRITE`, then
runs the fixed UID/GID 65534 inert file fixture inside the measured cgroup.

The fixture blocks until the protected sensor handles each permission event. The sensor requires
the exact child PID on open and access permission events, writes an explicit `FAN_ALLOW` response
for every permission request, observes exactly five successful permission responses, and rejects
any missing open, access, write, persistence, mmap, or final filesystem-diff observation. The mmap
blind spot is separately correlated through the measured BPF syscall sensor. The fixture cannot
read or write the protected sensor, and no raw path is included in canonical evidence.

The hard-coded fanotify class, mark scope, and masks are bound through the measured sensor digest,
signed-image manifest, backend identity, run spec, challenge, and guest receipt. Strict Rust and
Swift decoders require exactly five permission responses for this case, the exact eight-event
actor/cgroup sequence, healthy zero-drop evidence, BPF mmap corroboration, complete filesystem
state, and complete teardown. The older file cases retain their existing compatible minimum while
the closed platform gate is exact.

| Binding or observation | Final fanotify-permission case |
| --- | --- |
| Backend identity | `sha256:f2b1e29789c909d6b0c1e33b0937f96e64af1b0800aae4b9d718f59c0f10136b` |
| Entitled signed host helper | `sha256:fbdf884ed5f7139e93871197c0bf43eba242ea5c4c2989e5913650f9494d0355` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:17a19df3c325ee9996adbc4247ca241b6fefa826f276a8fec369c2fa44217155` |
| Guest signer | `sha256:a5ba0ebe8a25ee7e185f8743c4379030aad6cb49fd0918c87f30ff5d660ec112` |
| Protected sensor | `sha256:8afdf3052ca2acc415daf6efab9ea59d5c3d194eb8c05b565427911c7bf47301` |
| Fixture child | `sha256:90fe2ff70cafe77698c4b0d98d9bda3a73918912a6491786e73a86665a1a3aaf` |
| Signed-image manifest | `sha256:4a1432b30b7943bdfb51df23cdc3175555974edd011a08618f30562cc26d3f02` |
| fanotify group / mark | `FAN_CLASS_CONTENT`; mount-scoped |
| Permission masks | `FAN_OPEN_PERM`; `FAN_ACCESS_PERM` |
| Notification mask | `FAN_CLOSE_WRITE` |
| Permission responses | exactly `5`, all `FAN_ALLOW` |
| Actor / cgroup | UID/GID `65534`; PID `411`; cgroup ID `21` |
| Challenge | `sha256:ba9164b34b9352b271445ab51f0ee6805a839a8916bef9d280d99839dc00eb66` |
| Run spec | `sha256:ccf2e5f6cf4a7b4e2d986ff83ac0394875fab2789cc26b76660bfb9f6a969ea6` |
| Request frame | 5,066 bytes; `sha256:593f1b410d051d0cea075ad6e161905e6b120dbc445d4f0f032128f8311eadbb` |
| Guest file evidence | `sha256:5e4199ab3a0895678a3e577089fb5ca4056c667aa218c6dbfef5788b96effa0e` |
| Guest receipt | `sha256:cfd5874687a3423223d3ab80fccd33db0c19ccdad77016bf416828263859e37b` |
| Host lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:b29956b98473232ccde54a3d639d9322534929ddb9748eeaf849bd659072708e` |
| Sanitized serial | `sha256:ee1a492888ded0a0f911bc88cad1b82fdb9e9ef5885c27a394c897d49d32a0f1` |
| Guest events / guest drops | `8 / 0` |
| Raw frames / host drops | `0 / 0` |
| VM stopped / clone destroyed | `true / true` |
| Execution authority / package execution / sync-back | `false / false / false` |

Two independent local image builds were byte-identical and both passed the signed-image verifier.
All 36 implemented cases then ran physically on the final identity and passed the independent Rust
complete-case verifier. The gitignored inert evidence archive contains 249 files, including all
108 request inputs, and has SHA-256
`2c8612dcb33600242126f756ca1ffd9141c72a430f6e75e7d459c136286af0ad`.

The full Rust suite, 182 Swift tests, format and strict Clippy gates, deterministic 38-case fixture
contract, strict static aarch64-musl sensor and fixture builds, and all four repository smoke
harnesses passed before this checkpoint was committed.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, restricted, unknown, or
malware package code ran. The backend cannot issue package-execution authority. The next closed
gate is `bpf_program_types`, followed by `raw_frame_attachment`.
