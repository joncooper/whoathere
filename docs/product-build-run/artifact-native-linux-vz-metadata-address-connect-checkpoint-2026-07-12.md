# Artifact-Native Linux VZ Metadata-Address Connect Checkpoint

Date: 2026-07-12

Status: `metadata_address_connect` plus the fourteen earlier physical cases pass on one exact
measured backend identity; the backend remains `candidate_unqualified` with 23 of 38 cases pending

## Outcome

Root-owned setup assigns isolated source `169.254.169.253/24` to the guest NIC and installs a fixed
neighbor entry for canonical cloud metadata address `169.254.169.254`. The neighbor is an inert
guest-only sinkhole: nothing listens, no frame is forwarded, no external route exists, and no real
metadata service is contacted. The unprivileged fixture makes one nonblocking TCP connect to port
443 and holds the socket for observation.

Protected cgroup-filtered BPF requires the connect syscall between exec and exit. `/proc/net/tcp`
binds the exact child inode and ephemeral port to the metadata tuple in `SYN_SENT`. The host requires
one exact Ethernet/IPv4/TCP SYN, including MACs, tuple, flags, lengths, and valid IPv4 and TCP
checksums. A distinct `cloud_metadata` guest class and `ipv4_tcp_syn_metadata` host frame kind
prevent replay as ordinary link-local, RFC 1918, or documentation-network evidence.

| Binding or observation | Final metadata-address-connect case |
| --- | --- |
| Backend identity | `sha256:4b0da48eb4e65c9423aa605f9dd26bf913bde0a9944c916d8da8a7852184ed06` |
| Entitled signed host helper | `sha256:da766f3821866a9bac5e17f1146878edd9a36df1b7501f78a2442ef86828c351` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:64931d0405fdce3a1d0cdcc5da88b7054078669dde606da0f6607efb649b4739` |
| Guest signer | `sha256:aee1f82b559f8125bd93d9b81d2c5cbd32c43f9c632fff562e081852d4e8fc7c` |
| Protected sensor | `sha256:cd924e2937b935090438432293d1a7a32b5816b13d7908c31ec1230d35328e6e` |
| Fixture bundle | `sha256:c63791aa667623befd7372d4a71de05ca0fd79cdcbcae3809ea850c673ebcad9` |
| Signed-image manifest | `sha256:c94a794be0ed996add9047d010c70dcc5e36c7979062cc921e6027794c8d04fb` |
| Challenge | `sha256:5a9aff8b460acebdeef7b2abd0450752f84d9c7d936073f6a1f46632e70c5e45` |
| Run spec | `sha256:3fe778cbe9b1f2bc0f82f720704cea54c0c3145e51533f0f4af20fd1fe5dd69f` |
| Guest network evidence | `sha256:ae16c13cd63dd8c85e10500b73ec7ac5c68cd1a4326eb0a55aac159f3b1c497c` |
| Guest receipt | `sha256:89681d1bd0799248306ee0f06b240654573a43d548bb1f775312f9eaec3af5ac` |
| Host packet/lifecycle evidence | `sha256:e71e371f9297b5a0fd9feea5fffae7f8f2a8986c8f5747aef8920a755cf6b760` |
| Host receipt | `sha256:83e74b1f04fd8043e1b2708e5de08ac200fdece1cdd2fcd714e838621fee8747` |
| Sanitized serial | `sha256:1545ed2b8152d61b3cc6e10c5850b077b94b1fd191fd04b58b4eedecb36f3356` |
| Guest source / inert target | `169.254.169.253:47098` / `169.254.169.254:443` |
| Raw / matched / unexpected / forwarded frames | `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent image
verifier. All fourteen earlier cases were rerun physically on this exact identity and every
complete case was independently verified locally. The restricted, gitignored sanitized archive has
SHA-256 `fb005ae8d47cadb13e19750a55f472ba1f13afdcfd31614515b1c7a0ef702747`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. Fifteen of 38 cases pass on one exact identity. The backend cannot issue
package-execution authority. The next network-intent gate is `public_address_connect`.
