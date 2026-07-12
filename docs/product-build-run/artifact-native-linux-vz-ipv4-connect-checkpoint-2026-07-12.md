# Artifact-Native Linux VZ IPv4-Connect Checkpoint

Date: 2026-07-12

Status: `ipv4_connect` plus the eight earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 29 of 38 cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Dynamic-Library Checkpoint](artifact-native-linux-vz-dynamic-library-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The first network-intent case now uses only the existing host datagram sinkhole attachment, with no
external route or responder. The root-owned sensor disables IPv6 on the fixture interface, assigns
`192.0.2.2/24`, and installs a fixed neighbor for the RFC 5737 TEST-NET-1 target `192.0.2.1` at the
sinkhole-only MAC `02:57:48:4f:41:fe`. The unprivileged fixture makes one nonblocking TCP connect to
`192.0.2.1:443` and remains alive for bounded corroboration.

Protected cgroup-filtered BPF requires one connect syscall from the exact child between its exec and
exit. Live procfs independently binds the fixture's socket inode and ephemeral source port to the
exact `192.0.2.2:<port> -> 192.0.2.1:443` tuple in `SYN_SENT`. The fixture report corroborates the
target, source port, inode, and `EINPROGRESS`; it is not detection evidence by itself.

The host packet sensor separately requires exactly one Ethernet frame and parses it as an IPv4 TCP
SYN from the measured VM MAC to the fixed sinkhole MAC. It verifies the exact source and target
addresses, the guest-reported ephemeral source port, destination port 443, IP and TCP header lengths,
no fragmentation, SYN-only flags, no payload, and valid IP and TCP checksums. Any missing, additional,
or malformed frame fails closed. The host never forwards a frame.

The canonical guest network payload binds
`fork -> exec -> connect -> exit`, while the distinct host network payload binds the sinkhole-frame
observation into the VM and channel lifecycle. Swift and Rust independently decode both payloads,
cross-check the source port, verify the guest and host signatures, and reproduce the complete case.

| Binding or observation | IPv4-connect case |
| --- | --- |
| Backend identity | `sha256:c172ee215a043cc9a7b6df2f032d01e474b3917b7cf45ea3792662455ab3cd4d` |
| Signed host helper | `sha256:6d4169e96ec7665f29ac51cfc01bc5086246d0a14fe90026daf227ead3c5f2e8` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:44a06fd3dc8b60ef18f8b03ce0fa4ef4d95bc2b90c423d800bd85d2552c74995` |
| Measured guest signer | `sha256:09257940c47bb823e3a18a9860e2095545eba51dfcd9651d1dc8f2a1153ccdf0` |
| Measured sensor | `sha256:ad13b876468b6fcf498c8d535eb88061d77ff51d8097b96424d3018615baca5b` |
| Measured fixture bundle | `sha256:9cba083e75338bbad7e8f2f0e6274daab47ffa6c0a8bf4e50b0c176769f347ee` |
| Signed-image manifest | `sha256:6299d8709aa6dfe7b8ed544b6a7e2fca50dd0437b32a10b6ee162c32f31d4623` |
| Challenge | `sha256:4c8388013e081a471cd86de54e083c06091226e1b737bba1a4225cb2d7c301d0` |
| Run spec | `sha256:daed4df11f419ca9d86b781530d5e894b190a9bb0fc4e9c066ebb16ee1c22ccc` |
| Guest network evidence | `sha256:a358296143855b954809177b52c734d64f555438b8705ae27ced3007d5ac15af` |
| Guest receipt | `sha256:eb252cd70b494b75a20ada08ef6c5c93f35548c9fbf6ceb9768a3a76232e771a` |
| Host network evidence | `sha256:7e3647c12eb48c88a7cabb3bd457787dd80c82dd8d7f950b6b04a186f645f0f7` |
| Host receipt | `sha256:66a3761a96ddb1bd75f65d12e465b00ed938e25a98e54d22a70d0388e1895ffc` |
| Sanitized serial | `sha256:7b2c070b54ffcb115c4dd99b06cbacb08e594e9d57db1efe6557d5f39652afab` |
| Guest/host source port | `54432` / `54432` |
| Raw/matched/unexpected/external frames | `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

## Same-identity rebaseline

Changing the measured fixture, sensor, guest signer, initramfs, and host helper invalidated all eight
older receipts for qualification. Fresh physical runs passed and were independently verified:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:bb502119976e59da2e222075f6a8fa5cdae220e3a2be65c5bcf36e372c3a5c86` | `sha256:d0bb8d1cad4e955d6ea894f38f5d8706bd7938504fb7d8fb0af352362d9b305c` | `sha256:019366f4d88453bb7b7ca8fd97b914bdd954ab55b73b810a6bf827e36741b2b7` | `sha256:fe3e163fbf5931bad9ac0296d1bce87d18fb59187960a1d2668e4ce019a8c0fb` | `sha256:0f68352f74bcd7ca829f0bf0c7419455f508cac563f52ade06443e4a6c0629ab` | `sha256:7737ebeb946aa74883a542a535d6a93bc7408fb5f8dcb57a6b79d98cd6ffcc7f` |
| `protected_open_read_write_rename_delete` | `sha256:40c1ec35a3d6b7d83f545b6dfd9536153ae9e6ad3931da6edd5084949becf063` | `sha256:bed4087bac6755391ebd13bcc2fd000b0ecb50b5dc11930b960f56a35a1f8cd7` | `sha256:b00f0c0364c1ff0ad85ac959a47aa320197bae0a49ab4a1f9e01f653f3fdc519` | `sha256:0123cd292a15f97739fd288a9144ee502f3696a243ae88b9ea007446192ab8bf` | `sha256:f4be7ea4476eb98e580039eb0e9202b7f9dd2a034e2ed7cb9a4e7d4c747a88ed` | `sha256:36790f1a0bffc9f4a35dc2524fb3a1520f58157895e9e7242047b88a333db575` |
| `mmap_access` | `sha256:d7482fdfe6ad53be6b47450fa15623110cea00733e564ce32569dc243dc84c72` | `sha256:67842b48d4e3e248c78be7789f0311e4d9dfbb349dd35a3d0b0f2a5cf57f2098` | `sha256:7498bada46c834778e89f819ea46e8817519582b71d0abd071e851f2e585e128` | `sha256:3866d8c223f6bc0747c1202786ba1664730f27537c4b0b009ae471cd1208a86a` | `sha256:5f4422d5ac96b0b009cdf42f3704fc3ff0cc1ebce53ae335f2b0cb048fd34afc` | `sha256:8d4106e96d6c8790568a71b1c8dcd240e4156bf41f8fe9802f5759a6634c89a6` |
| `double_fork_daemonization` | `sha256:76ab70cfa2aadd6ae02a4174461379d2115d076bf12ca6a063965621a4a54a6c` | `sha256:9aadca4bea46b6f418e733a113bc1080b1be1daff4947b0c42ffc295b90f7d49` | `sha256:3886e235dab4454952cbbc6ee8ea64c05c0c564828cd62efeac76e327aca60aa` | `sha256:cd932b81e1bd13d432918edfae59646eb0e5d623dcd80b27923ce18556746a0c` | `sha256:b5625fdc9205509da40dad180fa8acfba8be2368aff69d25acc644846be51675` | `sha256:6bc4c7409f6359a07f19e2c269b757fa80d46af37a1a1d0ad049784c9fb276a1` |
| `reparenting` | `sha256:88451e5c695fc99fb87a9cd9538b9152218a54c3405db75f6a659f5a1ce19cbe` | `sha256:0533b508f89da2f6210ad4803abf18af0422f6c2b0a94a50a02d57aeb8454009` | `sha256:e1d5ab8008bed3ec3bc977cf7f443efeb3c52cc7a2d80fbc2ee7410cedb1a5f0` | `sha256:9e08d8850f4bbb275cd431fca4a0ce70a6ce1dfc0b0ecf428f48a935266a10a4` | `sha256:8f3f0fbb111fdce6616314ac7c9dcc2d00c68a278058fcd6cacdcecd747635c7` | `sha256:f81f6e5faf95a8c6c913e2b902d2b0ed47c05a3045940a17462fed2f848981ff` |
| `setsid_escape` | `sha256:1c088572424cacaf9722eebbd443d3b8d7a74c7ea1414f85fa025547e5475a17` | `sha256:493642eeb6ced084e5233559e5e21522f9a298d16c1e4a72cac34d1f9d40293d` | `sha256:4e3f9e3b6af5d359a97c93af6ebf854d7f59999e28826d67bdaffb24439a8b54` | `sha256:d0f17e94fec7dce981e4be1c28d756ee14fc768eac52907d8ab4359fa3eb1150` | `sha256:2629bd96058549503b3dec8334273ebd00434f0421e0249cc3b3b8367a8c2ffe` | `sha256:09c492a04a54d0f4e2dd11047b49cb015619c6aa5e3d11fd9089d3a4d286c0ab` |
| `credential_change` | `sha256:d70792ca0552051df0c720faf7a798cf58bb0b076983dde91817dc2489315a84` | `sha256:1607bcd076ad318a690153fdd753c986c4b5c9e916d1fa8a0702589a75cba836` | `sha256:61fb416130a145075d99c1b160a6a1e7406f768a4952e5c97b0e09490b452dad` | `sha256:ea7f10d9d75440213d3704b7c1750a5cf061f3b692d626803eea8554f2726668` | `sha256:2c529e001b6abebb71cca6aba07f789a46fbc127108d9afcc56c9de6c7e1d964` | `sha256:4a6eed553a00f1168a2d9c1ebf6078de8596b231a6dadd4839d9670d161a5dd9` |
| `dynamic_library_load` | `sha256:efc99db20f80322bca184a2aaa17d26f6707a83f354b9f91d19f341608601c41` | `sha256:bdc48cf2d7d063552d01e50bbb5c98a4c64cca533e6af80de88f7ddc826f55d8` | `sha256:d253978fa78be4763b995e69431f3d879d20ad9f722cd01ec9610dd9193cb8b7` | `sha256:043a6d72362f437112f4ff65aa09af2623f8f9c5f67fe193e24b8a3b6d045b65` | `sha256:6bc98037e07e6ac06b5ea852f31d4c5b088e7fe95796f1475b75eba1d2a323a2` | `sha256:cc1db47c34c60e6c6be6eceeb0f1affcca7207f5fb2fa18d6b6098c4048fe71e` |

Two clean signed-image builds were recursively byte-identical and passed the image verifier. A
pre-final physical spike also passed, but its receipt was not counted after the host frame parser
was moved into the tested core and the helper identity changed. The final IPv4 case and all eight
fresh rebaseline cases passed physically and passed the independent complete-case verifier.

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Nine of 38 cases pass on one exact identity. The backend
is not qualified and cannot issue package-execution authority. The next network-intent gate is the
closed `ipv6_connect` sinkhole case.
