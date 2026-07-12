# Artifact-Native Linux VZ Private-Address Connect Checkpoint

Date: 2026-07-12

Status: `private_address_connect` plus the twelve earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 25 of 38 cases pending

## Outcome

Root-owned setup assigns the isolated source `10.0.0.2/24` to the guest virtual NIC and installs a
fixed neighbor entry for the inert `10.0.0.1` target. The unprivileged
fixture makes one nonblocking TCP connection to `10.0.0.1:443` and holds the socket until
observation completes. Nothing listens at the target; no packet is forwarded, no external route
exists, and there is no storage device, package execution, or sync-back.

Protected cgroup-filtered BPF requires the exact connect syscall between exec and exit. Live
`/proc/net/tcp` separately binds the child socket inode and ephemeral source port to the exact
private tuple in `SYN_SENT`. The host raw-frame sensor requires exactly one Ethernet/IPv4/TCP SYN
from `10.0.0.2` to `10.0.0.1:443`, including the fixed MAC tuple, source port, lengths, flags, IPv4
checksum, and TCP checksum. Any other frame fails closed. The guest evidence also carries the
distinct `private_rfc1918` destination-class marker so this case cannot be replayed as the RFC 5737
documentation-network case.

| Binding or observation | Final private-address-connect case |
| --- | --- |
| Backend identity | `sha256:5c4c439fb8ddfc8e4a325760f8b55716885cc67dcdb2fbd618915d395b16a049` |
| Entitled signed host helper | `sha256:26ea1af0805fd125faf062613b38de0fb4978f91a9118d199d5c9b68173e38d2` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:0af4eba0c662502df8cd93843388302f6c334a8f5921760481945f03a7e0b7ca` |
| Guest signer | `sha256:55e00f0d4fa08e4c713b9a21eea46c234f8142e820625fe891503dfe1545adaf` |
| Protected sensor | `sha256:11b37bca1448501922f76ceca8e0eaefd1a1565f21741b4dc4ca36e05c4bcef0` |
| Fixture bundle | `sha256:ad9018379d51b45d78ef10d439c23f38399cd3f5dcaef4a630cae18be506eeec` |
| Signed-image manifest | `sha256:d771b0cccebe0064bb68b6af6ee96289e0e30d54a05fd8a5d841ca27343450e6` |
| Challenge | `sha256:ae4e273b0be98d99e4977dc62f5ba5b61156d6edc32c6ed9b35ddfa3bba31843` |
| Run spec | `sha256:53e8fcaebfa07716bbd3dd4e25624ad09874830e816da5ab1db063d9293b46a9` |
| Guest network evidence | `sha256:324d9b0c441498c14a4f8f334782c9a66629db768f090eecb9c26b49cf590aac` |
| Guest receipt | `sha256:ef61a901eddbed7b359c5741edbaf626472a6b21cf685d06f8a3bfbab047e10c` |
| Host packet/lifecycle evidence | `sha256:161e3b644012c5a76b07bf311e1365c5598df9162b302577cab0b3dcaf584587` |
| Host receipt | `sha256:430c27a14544077398268f395b9491e17521e6b91d53c1a07b9a5aa7d3ca0e29` |
| Sanitized serial | `sha256:174724837e3c9556159e76398dbf96ddfb78f76c0065c16caf0789ec60ffb8cf` |
| Guest source / inert target | `10.0.0.2:50956` / `10.0.0.1:443` |
| Raw / matched / unexpected / forwarded frames | `1` / `1` / `0` / `0` |
| IPv4 / TCP checksum valid | `true` / `true` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent
signed-image verifier. One command-line preflight was rejected before VM creation because the
expected image digests omitted the required `sha256:` prefix; it created no receipts and is not a
physical case. The corrected invocation produced the first and only counted physical receipt.

## Same-identity rebaseline

The changed fixture, sensor, guest signer, initramfs, decoder, and host helper invalidated the
previous twelve receipts. Fresh physical runs passed and were independently verified:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:469b4bdcc82a6e8bf15b4c315e4346f299935671852f6f328ffb10cdbb3017e3` | `sha256:dea7357ef7c9b39a553ac09f33b4507b8d930988652444198d9c387bd5af904c` | `sha256:d038f12583cfc6e121a0954ee8e5af0659478c99395409552c10b5dd28a4bd2a` | `sha256:5379617edbdb6badca2a9aef474eda343a989418115b84882e4476a3aea04bc8` | `sha256:b55d337ff31389cee023acfb8f5b30dffe44ee841cc765d81e02fdb38778cdd2` | `sha256:c3608a571889c207d55c45210320e3996a9f3813ce1a1b277f119848fb19515f` |
| `protected_open_read_write_rename_delete` | `sha256:dd4555c206a9402ad4d10ce2a19cfa6bb9e6f7d5cc130c2cec23f9a3d1dfdff3` | `sha256:a2f1c218016c00ce38dea44bd16755d933d57b00cbe481a4cd166b4e6ad022a3` | `sha256:0fe2567f2cd3070879d3f80cd9a4d0ab2484534740a0d21635430f89bb5f43c0` | `sha256:9b691c8006937a40199ff3e33e57809b1bcf7c3433ef6b1e4620563a112ee5d1` | `sha256:e637cd543512086c1b9605a6d4226b4281e6d99937ec55fe85ecaee854ef9525` | `sha256:f592a94002a6845ffbf934c9a894664bc544bd3aae6c29466b4fe93543e3087b` |
| `mmap_access` | `sha256:0ff4f608d5b9d5e884a910aad4ef98f79ee5482e43be4a28a9d12a69beb88610` | `sha256:830efa40d6f8690ccbc4eb803a8d87ca01806fb6ddf3442785270a67f40ad499` | `sha256:0388d9fdcd2b4f249fb8dcefd5a226a41d32b27f6a748051105c7395bc522316` | `sha256:44dc88944b96560c69a6f407b2a69cc8f208b36bc0c0d70eca3d4f4c1413baf5` | `sha256:bd27d21894de39ec9bcdbdf11a4cdfc0f693469c48dbdbb534fff976d8b329ff` | `sha256:17dcb9c73a8cb50734539549267addb1d750ace41f54b15bd8bf48f43b80e557` |
| `double_fork_daemonization` | `sha256:981ee3f9e10116fe3db2ed954565e0abce63ef66cbba872e1c1d60dfc31fd99d` | `sha256:4583826f6f0753f75351ce879c9f0f4493f8e50d13dd51925293245440000090` | `sha256:2f5cdee07d0b3506be92c361e833787834a598cf463e10bb8e2e71d522925dc4` | `sha256:67d03b6580517ab70c9b57a45b1d9118a9a4c7c2582cda7c71e88cdbdc7506e4` | `sha256:84e6f6552057e1fa9d79d6be77ac165126f0f126f83076f9769d0cbbb7770b22` | `sha256:a79b12a45d2cc6fb779616245238fb76d9d40bf13c7d2baed6ff8838c25a1423` |
| `reparenting` | `sha256:753a31a0f73b464496c507099e97816bdb043a89514e778b3d36d671b2f2159f` | `sha256:d2e952d65f6f69bee319358b79ffca5bb1014893dfd4eed08867a9979458f534` | `sha256:3ea77b061890b84b95ab51f1c97f4e54ee1b7592ed378540c1127876b3c63362` | `sha256:c08804a6b40f877608ab128495b9693f293ad36cb41f9a115df42dea06792b21` | `sha256:a3bd0cf613c459760ea9cb9c808f590e8b702553736139872ec599fadd398e6b` | `sha256:d973f8c08f440e799facc4e8c58a993554834c28330420c29b187d49d05c7261` |
| `setsid_escape` | `sha256:2a3b0a801eed4f6f17137edb44f7a52f5780a4317c7d2b67d0d4b046a8f58635` | `sha256:840c3914f0202794768c350ee0865abbf5001d823f6b934db439fdbb1ad25fe7` | `sha256:245f22fca3ea5ea74f17aabdecb51c9f254e250f682b5d3ca08784825f577e97` | `sha256:7a6f77b36a570f4b7217143a7f324e3cd2c38611cba1ab74a5216217541eb25c` | `sha256:6a2f230cdd5cb32a54a36dcfe31cb6202ed586ce41a6e6599cead801ecc079c8` | `sha256:278aa8b4735c612a8be2002aedda6dba2c6cc2e48e8575309012466276cc0d65` |
| `credential_change` | `sha256:ec05fefd340692cf0156c2d4a612d05c372c908432c93c2a09d49956f9001b44` | `sha256:ed4fc85025ad3befa434a904876f6a7d1c4dd64c5356bd3e7d37467574a74d67` | `sha256:8ff9022a1fb588be1e2cca7859ab81d5e50077adac465e40ef5e9547b42ab64d` | `sha256:fb2a25e5595e9654552b35c8c6175fb2015fff18ba4c93e6ab6d530d5ada3aab` | `sha256:cec6ab0498629f23fc2df61c79edc293855691b67de1e78bff27c9edb1acc47d` | `sha256:ab8fdbb4cb3883f9acc77f231e32e1f6a8ea2b0278037b3deeb3001456a90313` |
| `dynamic_library_load` | `sha256:910d75a5011203ab5a027068aa44beaf88287da209f0d9d6501c2fc66f5c27b7` | `sha256:daafd5043e52aee844b2e449e3455530dee3c81a6bc95bd5b5e6ff1bb319cd06` | `sha256:3f93d8a866a9c8dfe72606d85aa813f09c8194ffbcbe0cf7f2c1e79321c02b39` | `sha256:65677858a13224fb433cbc9a2dd6bda6eb8f51e24911bb8dc8846594dbe89cc3` | `sha256:a2d33f7399c33849d518dbdc51b8350c6badbed3067de7732e7778ac114a119d` | `sha256:21152984f9d72a5e9b467f1365916f28e423f025df9686f69c7b42b4b9d6ea83` |
| `ipv4_connect` | `sha256:bcd225d4a8dd80fed6f3bafd144b464de6dc6ee6eb4227c2bb8f757e2763298a` | `sha256:babd27eabe652b6eae6a7ee980fcc8743997410986a23875c74e2b2be2937560` | `sha256:f4d12b1fa3f7df1822badc903a04ae8e84408b8682b502a3cf2496e0a3ede721` | `sha256:352c85f74e0b59ff04f8994e5f23a228d24a1f21d84eb82b97bf63185df5f9b2` | `sha256:b2de8ccac20e9e77b3b387f54a5073aa6098168c06d73d48aac93f633cb0fc2a` | `sha256:da3c20fbdf3fad4c56b83ad0597412ce8b5b93a693a969036b7fd00c4836b723` |
| `ipv6_connect` | `sha256:3d1c35d34a87b3209fa85ba1dfc6a415b5fe6b0cae2fc265fc33ac6ffea5e52c` | `sha256:4f15e02f2479a3b27eab2683ebf3b7c0214a951e5308c319743b25b9fbde37a4` | `sha256:c9fb27c9f3170552d3698178d71b3231168c9fcbc5bc571e05e66dc98c4977f5` | `sha256:be7d1b238b324a81da97826a7f0874fe953eb328a236126a0d547d755767f1dc` | `sha256:1a2b25e9511e46c6ebcba87bd54485ef66f328d27037a2b0551dbbf01f3ff475` | `sha256:db3c6178ca3240ba7f3ff779c9aa6d2da0c5975b9c385113f66969f21baf4207` |
| `udp_send` | `sha256:436d1ae6e28b4a74b1515db9ea6f26d7766bbe7febbf40e02829f5fc030f9e68` | `sha256:e98c4b5806ff5bde910208aef707d4824a24940e0fc92578e9f968e572f1776f` | `sha256:6323da7df8baff745e6fa5c1969d0c667c66e5a3e19107b19c29256a2ad51097` | `sha256:4de7ac6facfcfb9d09edc28488beee6af4f06986108b2c32d516f8481f997e21` | `sha256:70cfe62a6ff4fcbe238a2eb55fbf9f5dd3013749372cc96b2422268dc6ffc6df` | `sha256:63869ba036147c127dd98a477ca785cc0f45f00fbc0711427e3ebb2d0808d51f` |
| `loopback_connect` | `sha256:e094f4f5d28770e6856c12b3e24abba525b3d404b5302e4ee9b2d0c26137e43b` | `sha256:385a60588a1ac78e5b43c0543efa3216dad5a30c15f272bb471e646c71a0ccdd` | `sha256:d5d7d7238163a049e3f9ac62b47eab039c95debe49f91421f7790149a18b63ae` | `sha256:f52047580081ac320643682aa60ce8ac4738ccde052f7850f208ab0cb03e715d` | `sha256:a6320739bc7ed95d587709f4b66d1df1dc8ed146da34a359d49be6fa5ebc32a5` | `sha256:7f2000240049e1e200066dac32f7bdd9792ca5f6def760f848081ca7b289722b` |

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Thirteen of 38 cases pass on one exact identity. The
backend is not qualified and cannot issue package-execution authority. The next network-intent gate
is the closed `link_local_connect` case.
