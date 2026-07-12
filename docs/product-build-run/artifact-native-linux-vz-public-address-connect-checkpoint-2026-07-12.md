# Artifact-Native Linux VZ Public-Address Connect Checkpoint

Date: 2026-07-12

Status: `public_address_connect` plus the fifteen earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 22 of 38 cases pending

## Outcome

Root-owned setup assigns isolated RFC 5737 documentation address `198.51.100.2/24` to the guest NIC
and installs a fixed neighbor entry for `198.51.100.1`. The neighbor is an inert guest-only
sinkhole: nothing listens, no frame is forwarded, no external route exists, and no live public
endpoint is contacted. The unprivileged fixture makes one nonblocking TCP connect to port 443 and
holds the socket for observation.

Protected cgroup-filtered BPF requires the connect syscall between exec and exit. `/proc/net/tcp`
binds the exact child inode and ephemeral port to the documentation-network tuple in `SYN_SENT`.
The host requires one exact Ethernet/IPv4/TCP SYN, including MACs, tuple, flags, lengths, and valid
IPv4 and TCP checksums. A distinct `public_documentation` guest class and `ipv4_tcp_syn_public` host
frame kind prevent replay as generic IPv4-connect, private, link-local, or metadata evidence.

| Binding or observation | Final public-address-connect case |
| --- | --- |
| Backend identity | `sha256:10da57ceeaecac3f8e822d6a66d8701caaed103c81a3b331b4d7a2766b64de16` |
| Entitled signed host helper | `sha256:ad998c02bfa423ba1a845f312fd1fa23edda68aaa4d7c0902914d315c4759e8c` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:b81a9ae32e07d32ae2f2b3ce86e9f9df581c4caab39ec75f9181f580097e8988` |
| Guest signer | `sha256:16ded282822fcc1dac581c94d72ba0d875e9c76015cfb1e1799e6f1324f8824c` |
| Protected sensor | `sha256:05eff54b0322ab04e082d2d87abbb0ddbbb8d8ed9a1a1eec6e6d774c7bc52789` |
| Fixture bundle | `sha256:03ff957ccdd0fa27374eac7c6689c443d37839b0a9b4c78525cade0d2a4f0e88` |
| Signed-image manifest | `sha256:d85a2b6c19313d42f9821f9e724a3e57e2f0448427e8db944424bcea706808fd` |
| Challenge | `sha256:a8e8f6cbdd2bb447f75afbc311366e69cc85e6c0aabe1249a21ee0cf6b6aec9f` |
| Run spec | `sha256:02026f905b4c3fe00e18138d3ab5af5ce99f87f7e0b31bd91c8d6a6eece652fa` |
| Guest network evidence | `sha256:4163041774a6bea10c559ca34e47bd6ff3110de6760efe9a7f365fec7e5c2441` |
| Guest receipt | `sha256:463350c978b4992cfaf27b769853c868532c191046b98dde4a87e8fd413aad60` |
| Host packet/lifecycle evidence | `sha256:3828cc692dd89a859ca3eef204463adb7c7c8e1871eff829170ead4cb23a74dc` |
| Host receipt | `sha256:3a9c4938a76113a8d06067924d2c47c6cb0f183b0400c45445322cfb279e56a7` |
| Sanitized serial | `sha256:b860b6c9929be70f2a549fa6a6b5d19f9c6da087637853c56c310aaccbeacb00` |
| Guest source / inert target | `198.51.100.2:35720` / `198.51.100.1:443` |
| Raw / matched / unexpected / forwarded frames | `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent image
verifier. All fifteen earlier cases were rerun physically on this exact identity and every complete
case was independently verified locally. The restricted, gitignored sanitized archive has SHA-256
`61649fb09d84b38c6669fbe70c763e0a438dcd2a48acc4a4b7dfe4d09d1f9c1e`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. Sixteen of 38 cases pass on one exact identity. The backend cannot issue
package-execution authority. The next network-intent gate is `dns_plaintext`.
