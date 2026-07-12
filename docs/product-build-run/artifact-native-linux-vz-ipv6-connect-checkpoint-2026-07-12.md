# Artifact-Native Linux VZ IPv6-Connect Checkpoint

Date: 2026-07-12

Status: `ipv6_connect` plus the nine earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 28 of 38 cases pending

## Outcome

The unprivileged fixture makes one nonblocking TCP connection from `2001:db8::2` to the RFC 3849
documentation target `2001:db8::1:443`. Root-owned setup disables autoconfiguration, router
solicitation, DAD, and automatic link-local address generation, installs the fixed `/64` address
and permanent sinkhole neighbor through netlink, and moves the MLDv2 repeat interval beyond the
bounded run. There is no external route, responder, storage device, package execution, or sync-back.

Protected cgroup-filtered BPF requires the exact connect syscall between exec and exit. Live
`/proc/net/tcp6` separately binds the child socket inode and ephemeral source port to the exact tuple
in `SYN_SENT`. The host requires exactly two checksum-valid Ethernet frames: one MLDv2 membership
report for the fixed solicited-node multicast group and one TCP SYN to the fixed sinkhole MAC. It
requires zero additional frames and never forwards either frame. Swift and Rust independently
decode the distinct IPv6 evidence, cross-check the source port, verify both signatures, and
reproduce the complete case.

| Binding or observation | Final IPv6-connect case |
| --- | --- |
| Backend identity | `sha256:31f2315f1c3eba2291b60c08dd77675e2bcf9e32141b0e0e38e6c0de97798cd0` |
| Signed host helper | `sha256:5ed92bb016de7d47822c98c3a0f373d2fb5fbcaa5f1c72cea043e77370980c27` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:57644e3038457b049c287c7ce2ee8e7c566c04a2fe25b8d64611c91cc18a438c` |
| Guest signer | `sha256:4b447cde102998300560f56341873903294641d2034323c8446d07d8fe47a73a` |
| Protected sensor | `sha256:4e8a3ce2aa08065db2ef19860d5f38590e8f4e97a3e8a6111ff14b9a89dd3f28` |
| Fixture bundle | `sha256:43e2218845e7e97011abc7fb0d2aee159a6a40dd2d3d43f1859f3cbce62b48df` |
| Signed-image manifest | `sha256:9b0b22e49ba80de704ab32182e1233dd062b68ce7feff850969f16f265618b3b` |
| Challenge | `sha256:40f4f9f1da28aaa36ac32ce9fdae58e0d3857de03c1e98c41feae976b71e6523` |
| Run spec | `sha256:4bfb4d6e02fb567236665a85deb042faee271d67403951954bb332e40570a09f` |
| Guest network evidence | `sha256:a817002896425318f1552c1890b897256a4da6d7904e02eaf898943fde812897` |
| Guest receipt | `sha256:14842e2651cbe164d4af053705ebdb4083a27cdb8dd9b737a26a0aba77f4e18f` |
| Host network evidence | `sha256:86a82d2af6edf12183d4d8d1edb2fd9eedd35f5bcba1a1a739f2bea41b5d8d47` |
| Host receipt | `sha256:ebf2dcc4aeb13cad8682e9578759fa0a47a8af9cedb6c533577e00350b3346aa` |
| Sanitized serial | `sha256:c7543057d8104ce958bacf82e68895fdaaffa70804d7e0ae7fe79bfe4b89df02` |
| Guest/host source port | `54886` / `54886` |
| Raw / MLDv2 bootstrap / SYN / unexpected / forwarded frames | `2` / `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the signed-image verifier.
Two diagnostic-only fail-closed runs identified and bounded the kernel MLDv2 bootstrap traffic;
neither is counted. The final measured run is the first IPv6 receipt counted here.

## Same-identity rebaseline

Changing the fixture, sensor, guest signer, initramfs, host evidence schema, and host helper
invalidated the previous nine receipts. Fresh physical runs passed and were independently verified:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:745832f200053e0baa62e6c524008b5662aa779c2fdea9bfb3ca0544056301d6` | `sha256:51e505047fb4512f6fd466a225f84f3c3011ea397de0ad75a25b96dd891dc76c` | `sha256:ac58352e92682ba7fd16384da69a107b55213a98aeb8b31764601b2254912cab` | `sha256:fca8880f4655b07eda3f078def8d7f1dde5c20a9ec94bc54f06344c891fc64f6` | `sha256:1d305855ee2c524ff3589cac06128b254387bf09639f9a558e3dcbcab3cef483` | `sha256:cb42fe77dc39d4315ebe31fff297e6130f75307f78d5f7c62aadb3a78dabae47` |
| `protected_open_read_write_rename_delete` | `sha256:0d3b906acc46dbcefab1870464e54d6a0624edf52cf893a49c989927bf719cff` | `sha256:de8f64b8caae57a212d1c6e1dfd502fba844f3b63779cb4f9c7c3b19cbeb98e5` | `sha256:a45c15e24037b0150e0829b003ab5df8e6b5751011b8dbf5d98bc3bb75193e24` | `sha256:a9c944aaf39723f687650feb7e9be697afb0f3fcf39d59c2be389a5bea0a1b00` | `sha256:25b61f21ce89e0fccc5d03cf824058a97ab3f62737c4da97ce36b604b1b470a8` | `sha256:e15e3559e446f8039841a602bb6d57fc146999b410bb5af9e493762656e3ac6b` |
| `mmap_access` | `sha256:ffe08d0e9e5940da3b62536d05de466ac24eeed169a8516f81f30f748aabdd58` | `sha256:d7104d16e73ef17f215eb223f7afa14ee18b0277f5ee955d0f5c534cbeca8b0a` | `sha256:f98d6fe9b97761bbedee12771e5cd05e5759b78cbeaa86f48edd795017a543fc` | `sha256:43de8c88d963bf5f8d82a68a991702828cef7cc566761ed87f1a1a512d92fe53` | `sha256:b7e4711736bb8fa9e43cff9a3a5246980fa9c8cb1ca88c5c63217f4910ba4028` | `sha256:c26dec5f46bcc0d55447de34b52260282ff95612a144576dfd67b3a38fc3f493` |
| `double_fork_daemonization` | `sha256:dfa2d12e3f21a63f1731ef8d7451edd7bb3617cf65f23884346b2ea0e8f8bf60` | `sha256:e6fefa94b7018ea4310f8fde561015eebf10a0b393e2532a1ea8b842478d0bba` | `sha256:6e81a92646480f3904571655e40a29564791ae1f5fed465adf0c9f372dd1ec0f` | `sha256:4e23b7186a6226dc0ef5d43939c9c0c5fde404ce129fb3a1e1549dc0648c87be` | `sha256:bad656c6eaeb5f09f0dc27c952e66be7ba28f87cc987aed71ac66b0077bb7a7c` | `sha256:ec791918f984612851a17f2ebef81d7107514b6922b076efaca33739097acd46` |
| `reparenting` | `sha256:be2726b0206e36de8904062ccc50eb93d90a9a4142e31e0b5be3e5cbe65f5bdf` | `sha256:c07d1eee0ec012e8331fef73cc92b9b949e0a2d5e29811764e87c365485aaa72` | `sha256:03fc04213607b3a0b8b8ca9b54e772d22382177077122fa6e8682f1fab5d6eb7` | `sha256:7661df83267c27a7dfe528ab33c9c32e5d1087b26e411be2e336934f28ce3db1` | `sha256:7fa4c2d0fc95a1bd97b1ecf7ff22066116a4ff2f030064c3bb807492821b19de` | `sha256:959fa57ee9df93808d581f6dbc7d498bc45b181c39db9b231d0c3db92c9e7fc2` |
| `setsid_escape` | `sha256:bd2c67bffa006104e77cb83001c295663c22d9ecab5d8c7384a5a81cf152b113` | `sha256:ad4ba2928917e57afa6739c99d489c8043c75699519173f405f889f0716ca2b5` | `sha256:ca3bbba89bdc19a0e517f3f2f02bdf05b68639d11e20b21f89e00474e5fd37ca` | `sha256:7727489727b89129dc7bc641ffb7497ff88d0b4826c97a8709be55b1e40f1e5f` | `sha256:e124f328d079389aad5a65bd2e2050bfd2eec70f507775adcfc7ac65391abba9` | `sha256:c4fb69e36d5fe229c838023180d77ac369b1bdd193b65682344315dfa4ad309a` |
| `credential_change` | `sha256:730f87f4341572bfa4a4f2cf0124c0173e694a40fb6c172b40a9b0180cd9c1ac` | `sha256:ec101a0214d1a5d432ed5d0f4d61d1514c6b394c231076b69cbcdf0555a09d15` | `sha256:948bfbaf3fe6833e5b5848507eb5a8e4f6d308a36fc5d755c3c5e668994ecef0` | `sha256:0dc32a71d5d9d4527c8b476c87383dbfc59e55fed2a7bab6ad1e937401741f7e` | `sha256:a89355083d01aff7e51d2135e3f0f541fffb9937260450d9ebbbab8645459ef2` | `sha256:b437191d4ef850f54a61abd575ed8a13137b4d364015225785225794ba045f03` |
| `dynamic_library_load` | `sha256:170b50a5b865b5567af80312760899656b29917139477c36e3e07146d4f04942` | `sha256:6015943dcbded0a4cf8d595227e65ec4c1181e4ec3d50d05d320ffe81bd1c4f8` | `sha256:e35b0cb5963087e5e2a2bb4643ad6389e7fc070f1f8934c24c5920d563f44562` | `sha256:04b09dbad13067745f7615a57f29f07d0198538493650bc9d18bded67f42e90d` | `sha256:e31bb006ff7467960e06234be8bdaa0b4b5732eece0dc7350e44041bebe534db` | `sha256:53046d08a7872083cb4b511698bd943db077bbaefbc9e06f3e9e2caef11bee8c` |
| `ipv4_connect` | `sha256:7b77637e0e2b5158a9f51e44ea5ac263f0b10a9fea2c929ff6a1ac1fd398fc47` | `sha256:5e63ab8dddbf484d4d920c4e2130c1689485e5d80a697ae60320f643fd4ee538` | `sha256:e4d31b39f70658c1284a4c5354b0b66ab4190f5140004d4db2eb59f9f742da90` | `sha256:9c4d1c0ba0189380e03b4869857b55dc89998d676381d68b579e8897c8cd8f06` | `sha256:7d5c794a29df27f1e1974f3358f05c5fbec414f609e48730b1b376d3b2ec81d4` | `sha256:050f85281eecaf06726e261a77f1a44aa64cbfab189f6cfadd22bbd0169cfa3a` |

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Ten of 38 cases pass on one exact identity. The backend is
not qualified and cannot issue package-execution authority. The next network-intent gate is the
closed `udp_send` documentation-sinkhole case.
