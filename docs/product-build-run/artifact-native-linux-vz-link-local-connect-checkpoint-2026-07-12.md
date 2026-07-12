# Artifact-Native Linux VZ Link-Local Connect Checkpoint

Date: 2026-07-12

Status: `link_local_connect` plus the thirteen earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 24 of 38 cases pending

## Outcome

Root-owned setup assigns isolated source `169.254.100.2/24` to the guest NIC and installs a fixed
neighbor entry for inert target `169.254.100.1`. This deliberately avoids the separately reserved
`metadata_address_connect` target. The unprivileged fixture makes one nonblocking TCP connect to
port 443 and holds the socket for observation. Nothing listens or forwards the frame.

Protected cgroup-filtered BPF requires the connect syscall between exec and exit. `/proc/net/tcp`
binds the exact child inode and ephemeral port to the link-local tuple in `SYN_SENT`. The host
requires one exact Ethernet/IPv4/TCP SYN, including MACs, tuple, flags, lengths, and valid IPv4 and
TCP checksums. A distinct `link_local` class marker and `ipv4_tcp_syn_link_local` frame kind prevent
replay as documentation, RFC 1918, or metadata-address evidence.

| Binding or observation | Final link-local-connect case |
| --- | --- |
| Backend identity | `sha256:87b6043eee6d5f72a9972e6afe08c007d96c0db2471aba81fc4c9435cc25519c` |
| Entitled signed host helper | `sha256:d2eb4baec29082fe80f775b57a2a8632c75b20b29555ad320674ac86de3fab25` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:0884faa444aa39da21d57534b0071065423a4b13b9049a38eb7aa5d8b708cadf` |
| Guest signer | `sha256:441fc4099676ecd35c2d6bca757317cf2aa156a100799b3c77fd83840083b8e6` |
| Protected sensor | `sha256:39e6d989c76ac015ebb2cd26ca66f0a4f2c4198ce0630d9c8b1404f658e75217` |
| Fixture bundle | `sha256:afa9348fcac546117c97ae328b65ca796b88435be44b945910cf57e520ebfb0c` |
| Signed-image manifest | `sha256:59da0cab040a5916842757938bee7c0d067e3c91de82b8380103ff890a461e2c` |
| Challenge | `sha256:451ecda00acb7e30e01748f790b016898c025840cfeab1e6c8e1e817361d8ab0` |
| Run spec | `sha256:3132b2160b7df0ccdc9711aaf240cc563ff34355a4c7f649e3ce092d45625393` |
| Guest network evidence | `sha256:8c362244a4cc51cca4ebb3662ac04ed47a2fbe0c954af3a0b6bfad0ff9a2902d` |
| Guest receipt | `sha256:56ca755b1d1731127a48a29dd6da9e1f166384db19086080546ef8dd630f783e` |
| Host packet/lifecycle evidence | `sha256:a5c8601fd1ce81b0887b3cb3880e598bdf7132bbe37867ece226a0a6d3a2d12e` |
| Host receipt | `sha256:84fdb710e736545f3e6c26ed0264432f0a058722cfdeb42b7637f4394146a2b1` |
| Sanitized serial | `sha256:aef042c399138c79fd15d324a3c0cfbd6ba190e729e84c11110face55e7eca8a` |
| Guest source / inert target | `169.254.100.2:34090` / `169.254.100.1:443` |
| Raw / matched / unexpected / forwarded frames | `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent image
verifier. All thirteen earlier cases were rerun physically on this exact identity and each complete
case was independently verified locally. The sanitized rebaseline archive is restricted and
gitignored; its SHA-256 is
`e0ef37fa6aa877cc8a69bfb872ab7f623065753ec536d6c2c23144f437856467`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. Fourteen of 38 cases pass on one exact identity. The backend cannot issue
package-execution authority. The next network-intent gate is `metadata_address_connect`.
