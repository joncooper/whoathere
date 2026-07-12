# Artifact-Native Linux VZ Plaintext DNS Checkpoint

Date: 2026-07-12

Status: `dns_plaintext` plus the sixteen earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 21 of 38 cases pending

## Outcome

Root-owned setup assigns isolated RFC 5737 address `192.0.2.2/24` to the guest NIC and installs a
fixed neighbor entry for inert DNS sinkhole `192.0.2.53`. Nothing listens, no frame is forwarded,
no external route exists, and no resolver or live endpoint is contacted. The unprivileged fixture
sends one fixed 35-byte UDP DNS query to port 53: transaction ID `0x5754`, standard-query and
recursion-desired flags, one question, and `whoathere.invalid. A IN` with no answer, authority, or
additional records.

Protected cgroup-filtered BPF requires the `sendto` syscall between exec and exit. `/proc/net/udp`
binds the exact child inode and ephemeral source port to the unconnected socket while the fixture is
live. The host requires one exact Ethernet/IPv4/UDP/DNS frame, including MACs, tuple, lengths,
nonzero valid checksums, transaction ID, flags, counts, label encoding, question type, and class. A
distinct `dns_query` guest action and `ipv4_udp_dns_plaintext_query` host frame kind prevent replay
as the generic fixed-payload UDP case.

| Binding or observation | Final plaintext-DNS case |
| --- | --- |
| Backend identity | `sha256:9afa1ea312978881c90f88ea07db37a3a5a0a450641dc2b55164336abf962ac4` |
| Entitled signed host helper | `sha256:39079f048719cd7033d5c43c484972a5b60c55efd674fa0b9cf2885fb855ee6f` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:83ac567e45566fa2801a4e8f9081713dbda4ccf9890f7074316ab84102bcb25f` |
| Guest signer | `sha256:619aeaa14d5f6f759bb4235e17e42089fa5dae1e805e11576992cfd581cf862c` |
| Protected sensor | `sha256:d79741676bc706690896c5ff1b5e1d45bb04e682ac56a1abd735d03f8dbbf029` |
| Fixture bundle | `sha256:9595f06bdba60eed74203471362516edc6cebe45f2dc29ffa763b35507e475de` |
| Signed-image manifest | `sha256:31b17ef37cc0433dcb817e7e47052ae79d76271076ba57dafb0012792e4cbbb0` |
| Challenge | `sha256:da90733daaad72b9670da4c58d33bd66c24bd23be42cf19eca627a0eda498934` |
| Run spec | `sha256:55d0c0f535c777bd2eb00fce0fff6ca2114ecc834cc9200932b36a4eb54f400b` |
| Guest network evidence | `sha256:88829a00d47173590dec95eb4a2b8ba7ecc0f613f7939f98ed17dec195f66447` |
| Guest receipt | `sha256:e801a8d150e4b77476444f2c7084345130cf6debbfd8e59ef2ffcad6a528f2ce` |
| Host packet/lifecycle evidence | `sha256:73ec84b4cf47e3344314e007619491d649528c323acf6b92d79e33e119b0d2ff` |
| Host receipt | `sha256:21a104466e0cc5e56a1e887703a117990cbdc5f2b6fcbe6f7bbb2cfb3e62041b` |
| Sanitized serial | `sha256:134922e26b58500a05a61787cf2cbcf70cb75b7b9ec00d3e99dffde4ba6b7b00` |
| Guest source / inert target | `192.0.2.2:45170` / `192.0.2.53:53` |
| DNS question | `whoathere.invalid. A IN` |
| Raw / matched / unexpected / forwarded frames | `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent image
verifier. All sixteen earlier cases were rerun physically on this exact identity and every complete
case was independently verified locally. The restricted, gitignored sanitized archive has SHA-256
`0c2e2dc5a75c776c729b54af8c2567e1852cad4a1d135bc488a1ca12375e9709`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. Seventeen of 38 cases pass on one exact identity. The backend cannot issue
package-execution authority. The next network-intent gate is `dns_malformed`.
