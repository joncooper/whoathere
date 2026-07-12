# Artifact-Native Linux VZ Loopback-Connect Checkpoint

Date: 2026-07-12

Status: `loopback_connect` plus the eleven earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 26 of 38 cases pending

## Outcome

Root-owned setup enables the otherwise-down loopback interface and opens a fixed listener on
`127.0.0.1:40552`. The unprivileged fixture makes one blocking TCP connection to that listener and
holds the socket until observation completes. There is no external route, responder outside the
guest, storage device, package execution, or sync-back.

Protected cgroup-filtered BPF requires the exact connect syscall between exec and exit. Live
`/proc/net/tcp` separately binds the child socket inode and ephemeral source port to the exact
loopback tuple in `ESTABLISHED`. The protected listener accepts one peer and corroborates that same
source port and target tuple. Because guest loopback is not visible on the virtual NIC, the host
does not claim packet-level tuple visibility; it independently requires zero raw NIC frames and
binds only VM lifecycle, guest-channel termination, and clone destruction. Swift and Rust decode
the guest network evidence, verify both signatures, select the distinct zero-frame host schema,
and reproduce the complete case.

| Binding or observation | Final loopback-connect case |
| --- | --- |
| Backend identity | `sha256:091ae28c384624243cc32d19f6c9c45635db6956bff1ab108e12738346c9ec7c` |
| Entitled signed host helper | `sha256:14db7c4f442c0cb5b03a07a6d9f1f3c84a08e40c2677be683e4479491b12bb23` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:331a9f4f023944606582f3fda15b54841705bb6d05c4e26ca77dfde778da324e` |
| Guest signer | `sha256:503443ab2060792660325424d4dc6d6d4ea1e674634027ad0cddb77f0f81722c` |
| Protected sensor | `sha256:cda0ef204b65c195f41a62c393d07c8ed09ce73f678fb930b007948345549b01` |
| Fixture bundle | `sha256:f181681e95bd4ec69bdecbe4575107088b94a6bb61a60b2cb54eefa74ff94e93` |
| Signed-image manifest | `sha256:e2aa91fb302d322047afffb44903abbbd2c8d8cab4269775f235e7deff728cb6` |
| Challenge | `sha256:40b5e11bcedb13f62d4715480ac6294bd441541eeb0e817e7dceb6bd225c9443` |
| Run spec | `sha256:9b0b17cbd91eeee59a2e77a532aea20a39c94159d1df5459dc98a5b903cfd0cf` |
| Guest network evidence | `sha256:2fb9978572365a9e846ee121257fce99eb1bcc8508dcf04c07653fa461b7b590` |
| Guest receipt | `sha256:b8d03998cd05ca6f9cbb7582ac830337f4c8de763f23836accaf70b401f81796` |
| Host zero-frame lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:f55da66a3eab3324bcc286a2e23a5a5806f7e07344d2d1464171dc928c44add9` |
| Sanitized serial | `sha256:25cebf550b7f31d2aaa6222efc2180380dcd9394738bb8c6fd3066612b26650e` |
| Guest source / listener target | `127.0.0.1:46228` / `127.0.0.1:40552` |
| Raw / matched / unexpected / forwarded frames | `0` / `0` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent
signed-image verifier. The first diagnostic run failed closed before receipt creation because the
minimal guest's loopback interface was down. Root-owned setup was changed to enable it explicitly;
the sensor and image identities, challenge, and run were rebuilt before the first counted receipt.

## Same-identity rebaseline

The changed fixture, sensor, guest signer, initramfs, decoder, and host helper invalidated the
previous eleven receipts. Fresh physical runs passed and were independently verified:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:159f4cbd4bac2f607a1ce206d59036f2dd337eb90aea5c5be92626f8bc373af1` | `sha256:06d337b0bd3cb9dd0b5fb053d015a4888fc6a446f3991c2b654059262d5aa3ea` | `sha256:ad19977bd34989e91c63dc3d40ec69eb2a2d39c51f329aaebb36a814476f66b9` | `sha256:f6f705097ce65d2f478480e2004d34cfcb764dbfcef5d23c4dc484c7976aa83c` | `sha256:ded62df01c74278fadbf5dd23eaa8ae99f2877b714cd28cf672844914f24d38e` | `sha256:2003daa53f8a0fef44fee9cfab9657f6c5532013fd8e2ab3520f288213c38c9d` |
| `protected_open_read_write_rename_delete` | `sha256:66c305b56614c70fd3d11793db6dfb4a81a59dd97bcecaaeb9df2768ee18e029` | `sha256:b16360b61ee8af7bffd31ae88950ee17dccbfc7a91e329f6f1d548d6aa4ecfa1` | `sha256:ed6848e06f81755831bdf09df148867a79d35b387c6d9879182ce22134a136d6` | `sha256:02a60d4ef2af4a1f1bc6789486ea0eaf2d858ecb732c274fbf3365defec11ce7` | `sha256:9fac7a6d058e26cc57305c188eaa46353f0ea8691c50913a911e19f20ea02647` | `sha256:dbbcf27df5ead1185eacb8344c728e1736b7e1e95b0889c4bb7ffcad62ae6952` |
| `mmap_access` | `sha256:9c303d242c844d4204cd95b4f77a472c08c7ef875c8b75dded0044bf761fe157` | `sha256:a0a8039666ab04680ddd38ca77a80d9ddbaf30fce6aaa7b01994b0bfbf88945d` | `sha256:d8ee65f58ca6f44a07d3bbe5f936899e5e24a4ef6ebb62007ff107f9d6f52af6` | `sha256:f715e00660b15be30c1d19804cfdf7860d5104764dc64ab8fa1d06db2eda2ad7` | `sha256:118c06116a30708b5c93aa49495aa19f7b3e50e8a74f2c97cf1a05a69cc297fb` | `sha256:e871917045b397214533c1dda23eaa4b09c8ea370880112dd859a1099d14644a` |
| `double_fork_daemonization` | `sha256:a6fa004ec3fb2efe1e0e75fd39f98140a15997eb423e4596b713418589abab50` | `sha256:8311143b756dfa08ba90963bb952bda3a410d22ce38ddfef40fe161a7817a285` | `sha256:a9d115eb15216698dfdc9fabd38b24581646788f663272d8bfab2a8038da31b3` | `sha256:5cffe12805d5dd2b25015ca8d6384a7e95416ce328377569af462d33842f2a16` | `sha256:deb3e4d53cefa046f678a48e8dc926005c3d28e14135902920cafea223db982a` | `sha256:957522331beeeb689ea9b4a50d7e7d3ac92f8f6d24d1ece0eb9b6d89f211662a` |
| `reparenting` | `sha256:df3f30b4b7f1bcb352da572476cd2e5aa0c30628a47cbea62460bf2d4b4da0c2` | `sha256:40a16864df3502b70732e5ff1add46c593191974511151bd34c2f4c688ca8419` | `sha256:e43806268bf099af4bdeb05ba52bf6b85a3103cbf8078416f6ef3eb4d44e43a8` | `sha256:26aa563e9a48919de3361dda303e2bbd83fde82f18de6548a0f4ab91853cea5a` | `sha256:50ce9b40d816895b2aafaacfdfdb02709ff9eeb6bbea9f8eb8568350d3fbcbdf` | `sha256:56f266e9c4f5ab68afdff7ed78b6149fc921d206b995466efe2d67f59b76474b` |
| `setsid_escape` | `sha256:8213b1b0b6a686b7b7294d71201d8680fde675b417d7926c95c78f219733f70e` | `sha256:72031cc6b975e6825cefbb8ccca714ee21d175fc478dda1eda9ede03f51b87c0` | `sha256:c674b20ef79206ccb0440944a4db48c634830400b81ba3f4c49eb7fffc539c72` | `sha256:75947e972170062b83601be23b5e664634bc251701a9fa5ea400f59e1b544567` | `sha256:259bd02f3a7b9f8bbee457ca73c85701ae0702c93e66be89d9d4e716b15f7618` | `sha256:1c74f00fdb10ec05969a6220135503f9e32360dccf43f29fa30b5ae9af76242f` |
| `credential_change` | `sha256:eeb0a40c5938325e063b39faf1d7eb6097a4b6ab1400db36192e4b892d57e2a8` | `sha256:065605df7cb5e54a2e346351aef28a4b12fa9c92e23027a3a5e7e3e49106f958` | `sha256:1004e3e995b29539e8421aac8e68c2fe5e59004884561ac839ea4393b0f637c9` | `sha256:c9f33b1ba87a8f71be2ee6b0bf182ca3a4d969e3e5eb2d56aeb6e3d977383027` | `sha256:ac726f2cd998d109dde05310483fe02f7e18a3a23de64f3bb4747d9fdfa9240c` | `sha256:377e5b5fb5bba588698ac3fa013eb4e5ef5ac2d0f689c8c8ba30c0ec67a44143` |
| `dynamic_library_load` | `sha256:1d7178bc0168dc1f5720c30869001e8128e48e95ecc7b6db84e6c039401ba2c9` | `sha256:e8e5cf0fb351c019fc9d6990990890d3f99f20b00d69ddb2ef216381005a5770` | `sha256:5506f06bfa4bcf7c366a84db6ff7a77ea22865fddaf4f692b82aa64d53ad0df0` | `sha256:a89434d9a7dcacedce013de758e213924f4122c7a75276ed459d2bb84439977d` | `sha256:e06f8151f5f53051f32fd3f0eb820216675a349dd0f875b20581918c9c762f4f` | `sha256:60d8581061ffa95e28fd0431f3e20f058606aac7c48c4cf7867d697d08b9a046` |
| `ipv4_connect` | `sha256:6c4da802112e5d625670f273228c2df520821e67aeb89642ebf16428982eea2e` | `sha256:607bafc0efbcf3226d6f1aad1cdf2b1b80e6f94cbecff18261de360a9715822c` | `sha256:7fa838412727fff0ace867844c89165eaa568a356b211a04e33be05bf33c9f9e` | `sha256:0535a55500200054c9b001126f9da2e32e09c5b1ef38d10d0951f11337918e20` | `sha256:2083bfddfc6748b54da2f89b3c4fa08e9181d8e59d7d080244eb3fcd52f1ff96` | `sha256:4105ab7b929be32aa00d8098fc54eba10ba7dbad2ca93166475bc9d8d83bf0e4` |
| `ipv6_connect` | `sha256:70cb6ea7fef6d2f411722d0e873a3b7c6f0a14b157609565f5ed619d8adef90d` | `sha256:c7c3ce1f33f61434ff769309d266a801d6b7493e174fcadd55a36ebe1208bd5f` | `sha256:87d9726712709dc026f60c20b929f4eab785f0c084c5cd80fe210bc12add2be2` | `sha256:b13493c7bc9475bc121023948f4ef84953f598db3c8ebf2de5cb26a85d2caa69` | `sha256:dcd930ca8e5ec9ccafa769ace49730e20471759b713a31226d13f836b1067755` | `sha256:7c1bd762ca96c99bfcf88eac6ade50f57310984195ad8fcec89bb7b28a20f652` |
| `udp_send` | `sha256:bee78723aec6d7f112be7d40bf7c97e01e18b96c9d9de9b28a9e885a5517b1ec` | `sha256:778790efc579976d3f011e7f3598ba51fe3099b025bb5f76cd169be5fbbfa967` | `sha256:36932b626c0b46fe40a1faef354a25b1762f1cdc639b44cb9fb95e63e076d9da` | `sha256:dc3556a3a4eb41003248256565f803ac49bc6da432962256ad7a8c8e69a348cc` | `sha256:db795fb557095d527af6f9b570ddc03c07ab162e75ba5ecda88c4ca928b81624` | `sha256:38a5e572f58b74a84ec3d5333c14d9cbf290cd32dbe92bf710b09f1e2a40d0e1` |

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Twelve of 38 cases pass on one exact identity. The backend
is not qualified and cannot issue package-execution authority. The next network-intent gate is the
closed `private_address_connect` case.
