# Artifact-Native Linux VZ Kernel-Config/BTF Checkpoint

Date: 2026-07-12

Status: `kernel_config_and_btf` plus the thirty-three earlier physical cases pass on one exact
measured backend identity; the backend remains `candidate_unqualified` with 4 of 38 cases pending

## Outcome

The first platform-capability gate binds the host-measured kernel configuration to the BTF bytes
exposed by the running guest kernel. The protected, measured guest signer reads the running release
and the bounded `/sys/kernel/btf/vmlinux` virtual file, requires the BTF header magic, hashes all
4,254,009 bytes, and rejects any mismatch with the backend identity before creating evidence.

The canonical payload binds release `6.18.35-0-virt`, the exact runtime BTF digest, its byte length
and magic, and the exact kernel-config digest already bound through the signed-image manifest,
backend identity, run spec, challenge, measured helper, and stable kernel image. It does not claim
that the guest can read a separate kernel-config file: the pinned kernel does not expose
`/proc/config.gz`. The evidence explicitly records `measured_backend_manifest` as the config
binding and requires the live BTF match to connect that measured build identity to the running
kernel.

Strict Rust and Swift implementations independently reject wrong release, BTF bytes, magic,
length, config digest, backend identity, noncanonical JSON, duplicates, drops, unhealthy status,
or a non-complete terminal.

| Binding or observation | Final kernel-config/BTF case |
| --- | --- |
| Backend identity | `sha256:6f5abb637be81c51e5dfcc15d0ee455af03662c438e27eb770e4419f74fdd88e` |
| Entitled signed host helper | `sha256:2d8ff2210e5ae0677e5442af3035132c2b280a0702b57b08587b8124452b3346` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:50a6f6bbe6238f52135ee23bbb335cab0f1b68a5b842d0e9c59ec9932d555ffd` |
| Guest signer | `sha256:e2489c73f0b0c6690cc6fa56a487378f86766dfc15638f343a3ab732a63af17d` |
| Protected process sensor | `sha256:1888030009504f9e382f669cab6dcd0f96e7de23c89d9e876b81b20c9290b60a` |
| Fixture child | `sha256:7e7a89c131266f020035f35787e8f052e6901b390deffb433a22ef85cf02c2f7` |
| Signed-image manifest | `sha256:9cbddb7ffb39695ac6beea9baad25bb3b3a2fd6f83c23c86741a906ad377df94` |
| Kernel config | `sha256:5557553d228d407e8eac80ea7a1c7bf36dab558625067c9ada355032cf6a9c51` |
| Runtime BTF | 4,254,009 bytes; `sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb` |
| Challenge | `sha256:c74221ad9a903b950815f1ea62d68cba4b8dd804a01f6bf5c809aeff302696f0` |
| Run spec | `sha256:298adad3dcc7a9bc0f900482c6b19d382f810b3e7886a88184f524755e532248` |
| Request frame | 5,078 bytes; `sha256:aa5877f4d981ee699330535f67d189543ea36dc75e0e588d9c7b9faaf49ec6b2` |
| Guest platform evidence | `sha256:f07686e9a28972e021258019634e9a7d099877a24cbf7ea7f404a47ff34375e3` |
| Guest receipt | `sha256:9ac5eef7f34a026442f4f4ac7a7254d83a4bed36a152edb633aaeae1294ae56a` |
| Host lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:09590b45d7ed9bcd7b17cc055edb0528817474de2462bda11ed0789f9918168b` |
| Sanitized serial | `sha256:923410c57c04bd3d41979057f04f0e7535217000c9737a023965320f8b46d9f3` |
| Guest events / guest drops | `2 / 0` |
| Raw frames / host drops | `0 / 0` |
| VM stopped / clone destroyed | `true / true` |
| Execution authority / package execution / sync-back | `false / false / false` |

Two independent local image builds were byte-identical. All 34 implemented cases ran physically on
the final identity. All 102 downloaded request inputs matched locally and every complete case
passed the independent Rust verifier. The restricted, gitignored inert evidence archive contains
303 files and has SHA-256
`0606c5f8ad5e9cc4d62550969d62631425fe65b6ef6b4ddc5976c7c84287af7d`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, restricted, unknown, or
malware package code ran. The backend cannot issue package-execution authority. The next closed
gate is `cgroup_v2`, followed by `fanotify_permission`, `bpf_program_types`, and
`raw_frame_attachment`.
