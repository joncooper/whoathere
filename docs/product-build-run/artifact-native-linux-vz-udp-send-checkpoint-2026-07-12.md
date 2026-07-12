# Artifact-Native Linux VZ UDP-Send Checkpoint

Date: 2026-07-12

Status: `udp_send` plus the ten earlier physical cases pass on one exact measured backend identity;
the backend remains `candidate_unqualified` with 27 of 38 cases pending

## Outcome

The unprivileged fixture binds a UDP socket to `192.0.2.2`, then makes one `sendto` syscall carrying
the fixed 16-byte inert marker `WHOATHERE_UDP_V1` to the RFC 5737 documentation target
`192.0.2.1:443`. Root-owned setup installs only the fixed local address and permanent sinkhole
neighbor. There is no external route, responder, storage device, package execution, or sync-back.

Protected cgroup-filtered BPF requires the exact `sendto` syscall between exec and exit. Live
`/proc/net/udp` separately binds the child socket inode and ephemeral source port to the exact local
address in the unconnected-bound state. The host requires exactly one Ethernet/IPv4/UDP frame with
the fixed MACs, tuple, IP checksum, nonzero valid UDP checksum, UDP length, and complete marker
payload. It rejects any changed or trailing payload, extra frame, forwarding, or missing checksum.
Swift and Rust independently decode the distinct UDP evidence, cross-check the source port, verify
both signatures, and reproduce the complete case.

| Binding or observation | Final UDP-send case |
| --- | --- |
| Backend identity | `sha256:0ddbb63b00eefbd3d19b56283f41e4bbaa3718d58236e3a1f014b2c21e80bfd3` |
| Entitled signed host helper | `sha256:22594610ac0613befc95bc1e5bc5b5fc8c2b86773a118eb9dcd8a47843135a5e` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:5228da6d9802bdeea1cd22bf1cda8501b92d16692a02054bd3fcc650ed9d13bc` |
| Guest signer | `sha256:aa2558827ac8f2e69da73c15cee00fe0681a0c7c31efb3bf38cdf06d088c44f7` |
| Protected sensor | `sha256:7163e6bdab580f654d976fb35af2f8c2bc194698b8444ce458af8b742cdd88d4` |
| Fixture bundle | `sha256:14bf4b3145fbe84b6cd0a09f3be397d9c355e44f812aaf05e5589ba04f1939ea` |
| Signed-image manifest | `sha256:ac5282d819f4a03698a5bd4e112dfe25176ac9878024ab8d276a449173c9bc60` |
| Challenge | `sha256:0c6c15e8d412853a46229b4d361842b6ffa099f41c5887baa833f7079536f152` |
| Run spec | `sha256:60ba52964fbe432021672a7e3e0062a20987bbb1d9714a7bd81856cc68dda95a` |
| Guest network evidence | `sha256:813518da445b7d67bc486c704fef6e09a2b0f68f3e1aa6310e1cab2c2325be86` |
| Guest receipt | `sha256:918b18456e01010043e1beefcdb7817fae4d98a66b7d7951f7f313e126cf8283` |
| Host network evidence | `sha256:c6f6b1e3108be1fde0052f2c3e245c641d17d72d602a09bb0418668be132bf86` |
| Host receipt | `sha256:51192ea6c64a5ad1da79ad2fe3e3eb16dc745c1fd6990b2c8d45232126515f3e` |
| Sanitized serial | `sha256:7f74ea8be19383ca603ad9d1cc87de74e7d58f295641b52846a6ffac7f6712f8` |
| Guest/host source port | `39051` / `39051` |
| Raw / bootstrap / UDP / unexpected / forwarded frames | `1` / `0` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent
signed-image verifier. An initial host preflight rejected a helper lacking Apple's virtualization
entitlement before VM start. That attempt produced no conformance receipt and is not counted. The
helper was re-signed with the repository entitlement, which changed its digest; the backend
identity, challenge, and run were all freshly rebuilt before the first counted VM execution.

## Same-identity rebaseline

Changing the fixture, sensor, guest signer, initramfs, host evidence decoder, and host helper
invalidated the previous ten receipts. Fresh physical runs passed and were independently verified:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:6174fdbbf27a93c867cac608088240c76d6267dd09c5c012e543b43587649bf9` | `sha256:a441ad831cc241a58cdbb333d534ab73ba68f569872a31ec0aa097560b7151e2` | `sha256:f6cc450b5cc4e8cff74aa97191210cc4813377a3829c41fcc6ba9b607807e55d` | `sha256:3c2ae96ff1bbfa9f9e25d25a7a4130143fd55820eaca3ac08c7c2fd74212435d` | `sha256:db863472160027bee76cf8a18b0e31545e017692beb7b5d51c34a101c305cb7c` | `sha256:683b4a7959e8888e8ab999ed67292d4e09f8a368868d23d97ef6839fd87cad26` |
| `protected_open_read_write_rename_delete` | `sha256:7913d27e5554cf91afec230b2b43704e3bdf1dbd14f6eaeeee7d281b36081f87` | `sha256:2d2ad6901b7ccda405610f1e93bed0c00dc6daa485fc159da5c6488aa0a871aa` | `sha256:c933e689043e305a30ecc15980312091edbb2712be531eba155d5de86c3c04fb` | `sha256:a2d9dd95a2a8d51dbd84e27fa56a12415df6bc233c5a0dcf8c554bb5d5c86d63` | `sha256:eca02e06c25206027a8d412f6793ec0db12fff5239c11118e2c08139abbee533` | `sha256:ce4110b53f27ce997b50739cf791a13098156534a5a5cd0031ee05ea9336cfac` |
| `mmap_access` | `sha256:ca5a819c6828d2cc270ca0675ea343a733dd45b0bdc109f14816b5d97fd14076` | `sha256:e1492853c992f7688238eef82a6aa27d6f12d0239f7de2fb9b95ca322ab1690f` | `sha256:d875677d4b78847eaa1d6beecd53c8a0a3e16e51d3e60d924670b1aeeedecd35` | `sha256:d5702e40f1cdb67d13f14338f769ba9934e0f92641738a1327f395ec1b3c751b` | `sha256:fdbe38106d8eaa691b6593093bc6931101f6716e7babbe98a73d711cce18b7fc` | `sha256:e30c27811d6411ccd6680923a3eab1630267ed954193bcec2ba50dd51a2d1be0` |
| `double_fork_daemonization` | `sha256:d9165856d9e969e8d45de8a6c9ed26a72bc7f7f50457ae4421a2e8122e4ac6cb` | `sha256:2e4c8f1b8a71d5bdeb72bbe46ec66e40ac856ed017786f8d9f59a98c80c6c9c6` | `sha256:d1b401c9db24550339578c39b21d3878ceb68863ad259623cc64387871f9a381` | `sha256:29a78ae69ca3f4b179887be93e79059c8bcf328ee5f772a353621c4cfd120b7a` | `sha256:b6004ac547f844de605a06b7bc57b1b911edd0853992a54f4f174f3ff496dd9c` | `sha256:97d19cafaf2e746796379baeba11e276352404287f4aa98848fdf1fcc6756869` |
| `reparenting` | `sha256:ce80bf927e549bd0ac6137ec27e86ad4def5b582f9f2c667a172e135f19a6089` | `sha256:aeeb9c54be6c21ee07161b7d76cd126f325a6094524d2c6cd5386355c7812a7c` | `sha256:87e1886b6d80c126957a21f52b77d1ee2824b3e95da1354c28daed5e79101beb` | `sha256:5653ebe6a32eee46764e3af5e17af0af5926da1c0a831578eebca6e70953c713` | `sha256:9ec2ba7453072a2552d9366ff9d84bf351aeffb64b5debdaea2d8694b4a9654f` | `sha256:ee652ecb8cc9edfc5781629f0a2c6932a6bd0478cf2b46a25a08998a0f56f877` |
| `setsid_escape` | `sha256:4a6be770bb4708dd3eef672e08874f86df3a2493e08b7cccd38db2d236d43ee3` | `sha256:3f024949be5eeee81ff4189f9afd910af5cad520b17e1c025d4cf20e17ce0731` | `sha256:e5981f6037bdaaef103b7458ea9acdc5a8eeb73f3dc37cc7cd4a3905d2d91631` | `sha256:2f59a2b33214c01f6472425974deb4928fb412e55a97b527755e93669c9c153b` | `sha256:c29ca3b292b0be89d328addb461c1e52b41bf7548bda8e13f72f3d4bb35aa924` | `sha256:be64c3ac5aad8322597869f6a7bff6019bb95dd5a5dda34852abe46e0fe323ca` |
| `credential_change` | `sha256:1f9d9ae5a499bac4140bcd70dc4d0762448d53229751c9d87d71540731536d1f` | `sha256:d29b9d6d34b7f9a248508f516e0994477ffd71412fc97dddb8bab2e12883edef` | `sha256:9c4197eb71d04e710da0a517c26cee9d79823922a142d31127683590c09fe518` | `sha256:1871e2ff59439fad089f7f4c83811fb963ad4f25b6a6b8a5a0c217d1312e371f` | `sha256:0f74f7050e3bf2d3aa345c5887c899a4f8833600d6cbf1bdec88380fdad10ccb` | `sha256:d6cb1ea62065eb75cc81affe5ba432300a2bccddb4344ace0dad904046070f4f` |
| `dynamic_library_load` | `sha256:aa76ff715c827a5bd67ed7ef82ceda983c76ebd8a5575e2bad6c5d2690d9bbd8` | `sha256:0b59f775f4699bbaa9710f635793f847672fdd3da7eaaa727bbe597618422b4c` | `sha256:0ba27537634a271bc4ea3d7689ea1bec294666bd3ee3a62fd61c439419276ae2` | `sha256:e85886fb733bb84a16c06193da42626c8fa1cfb6d95cbce32cde8eefb0c4b65f` | `sha256:e3c045eb0d2b9cb0b9d461bb642f475d043209197e6cee7bf1e9ecc6fab02053` | `sha256:4bb05ecbd6931afcec7664f6a533daf01471b15ac6d818ad4773b57f7a59eae9` |
| `ipv4_connect` | `sha256:e60230df990aa18b10930cc3cbf0c1fe16eedb4badd63c2f8fbbc1c8f52d8583` | `sha256:f4563d041ebe37fefbb843f5605c9a6ee1ed79aafbd652216774397598e639c0` | `sha256:71d92aab2122c22f5281c7aa02dd7fd332ca49c7df1ed26c346291c0c0c5c13f` | `sha256:87903c30107dfdfd97827d95fc8fdae53e91e80fc6d62c940b05a407dd55fd70` | `sha256:90ac1ed513ce6a4366440eeb8ed00c36dcc3336d50723e58c361a20acd9a63fe` | `sha256:0be444511903bb4ce7cb046c9b15c131a03e5513958ccb5a06ae048d76ae1042` |
| `ipv6_connect` | `sha256:7efae8c66cb4910129aa899c170e6dfa50d5ca3aea9bc0895bd177c062b715c1` | `sha256:e4b975412c67b7006f3555b15411c721dfa428dd1e09562165a060a38942346e` | `sha256:fbfd8d3306fc4ea38c1cfb040823f5ca63fe4bc1dcea6ed0a0315692bb03f37c` | `sha256:08e70d7fde37fc48bf774867cf802bf7d5697888e9c6437b561612bcf8af2f90` | `sha256:f8c644a1dffb6eb0a578aae433d44d633ad087f19ee80a35783a7c21feed51f3` | `sha256:778e56d043af2786d7e52a360058395cf7f6d6f95212a21be688b6904c07baed` |

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Eleven of 38 cases pass on one exact identity. The backend
is not qualified and cannot issue package-execution authority. The next network-intent gate is the
closed `loopback_connect` case.
