# Artifact-Native Linux VZ Malformed DNS Checkpoint

Date: 2026-07-12

Status: `dns_malformed` plus the seventeen earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 20 of 38 cases pending

## Outcome

Root-owned setup assigns isolated RFC 5737 address `192.0.2.2/24` to the guest NIC and installs a
fixed neighbor entry for inert DNS sinkhole `192.0.2.53`. Nothing listens, no frame is forwarded,
no external route exists, and no resolver or live endpoint is contacted. The unprivileged fixture
sends one fixed 12-byte UDP DNS payload to port 53: transaction ID `0x5755`, standard-query and
recursion-desired flags, and `QDCOUNT=1`, but no question body. The exact contradiction is therefore
one declared question whose encoded name, type, and class are absent.

Protected cgroup-filtered BPF requires the `sendto` syscall between exec and exit. `/proc/net/udp`
binds the exact child inode and ephemeral source port to the unconnected socket while the fixture is
live. The host requires one exact Ethernet/IPv4/UDP frame with valid, nonzero checksums and the
exact truncated DNS payload. A distinct `dns_malformed` guest action,
`question_declared_body_absent` shape marker, and `ipv4_udp_dns_malformed_truncated_question` host
frame kind prevent a valid DNS query or the generic fixed-payload UDP case from satisfying this
gate.

| Binding or observation | Final malformed-DNS case |
| --- | --- |
| Backend identity | `sha256:c8ac03e60e1e60898f89f0b97f98458f2a8fa24b5f52ab422ac428a2a10c3e56` |
| Entitled signed host helper | `sha256:30049f1da5144a32a464506b80f4621d50f9cf754759a25acffede3ed2aef884` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:b749d47b6793890bd6e8eaf89e789a64cce4c11823a2f0744527689c7c54e563` |
| Guest signer | `sha256:a602030b0ca3574a0077d398deb0ad81445484f0b42abc3b8c5350527f177327` |
| Protected sensor | `sha256:e26f58bf4ecec5f2c4e52ed2cc9ab7ad375147a32fa0afb66af5de2a046efea0` |
| Fixture bundle | `sha256:ed3835da0d5ab7dae5eebcfb5e9b50b736a11cdb87b013094cff3a9a91fc82a8` |
| Signed-image manifest | `sha256:a73b8a8e57945ed7dce00f4f310106fc4b8d3793b22efa9d26de7c2d50ee726f` |
| Challenge | `sha256:50d1a8e4afb9d30c9463bf463b2382ca401ab9ac32d6fecea145badd1dd39225` |
| Run spec | `sha256:73ac5aac069139415d040ede9dfb780325cc6221a543fdbf8be03b1f1fd132b1` |
| Guest network evidence | `sha256:8c7495d7c403cb5fab1af1a8c525226ff9c74e071e661608917733c98b0f6aa6` |
| Guest receipt | `sha256:4fa7afbb122f7941c40b10850babc0cf3967f8115897351997bb2a42648a9b27` |
| Host packet/lifecycle evidence | `sha256:6550af46b33d01e67a58960e8cd84b96a7e500c8d98cb08e530e32e0b78ee099` |
| Host receipt | `sha256:db8de4cd3c14eb4ca8bb9993aae4d137d740d8ae9bf224b0f041017eebc6bbd7` |
| Sanitized serial | `sha256:5a9fb16ffa8a4e19edf267bdd6d696d89d8b7eaf517d515d614347fa64eb9966` |
| Guest source / inert target | `192.0.2.2:48040` / `192.0.2.53:53` |
| DNS shape | transaction `0x5755`; `QDCOUNT=1`; question body absent |
| Raw / matched / unexpected / forwarded frames | `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent image
verifier. All seventeen earlier cases were rerun physically on this exact identity and every
complete case was independently verified locally. The restricted, gitignored sanitized archive has
SHA-256 `a7ddb48812dd5d33d57df943af02fc7130de1b8d38d359361498959ac9e15e79`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. Eighteen of 38 cases pass on one exact identity. The backend cannot issue
package-execution authority. The next network-intent gate is `encrypted_dns_connect`.
