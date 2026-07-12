# Artifact-Native Linux VZ Encrypted DNS Connect Checkpoint

Date: 2026-07-12

Status: `encrypted_dns_connect` plus the eighteen earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 19 of 38 cases pending

## Outcome

Root-owned setup assigns isolated RFC 5737 address `192.0.2.2/24` to the guest NIC and installs a
fixed neighbor entry for inert DNS sinkhole `192.0.2.53`. Nothing listens, no frame is forwarded,
no external route exists, and no resolver or live endpoint is contacted. The unprivileged fixture
opens one nonblocking TCP connection to port 853, the assigned DNS-over-TLS port, and receives
`EINPROGRESS` rather than completing a connection.

Protected cgroup-filtered BPF requires the `connect` syscall between exec and exit. `/proc/net/tcp`
binds the exact child inode, local address and ephemeral port, remote address and port, and
`SYN_SENT` state while the fixture is live. The host requires one exact Ethernet/IPv4/TCP SYN with
valid, nonzero checksums and the same tuple. A distinct `encrypted_dns_connect` guest action,
`dot` encryption-intent marker, and `ipv4_tcp_syn_dot_port` host frame kind prevent ordinary HTTPS
or any earlier DNS case from satisfying this gate.

This evidence proves connection intent to a DNS-over-TLS port. It does not claim that a TLS
handshake occurred, encrypted bytes were exchanged, or DNS content was observed.

| Binding or observation | Final encrypted-DNS-connect case |
| --- | --- |
| Backend identity | `sha256:e3c56db9b51e3036c6909ce8cd49a1cd37edfff7eef949fb5340255c32cc498c` |
| Entitled signed host helper | `sha256:14e092f28512b6cc90d59fa5dd4ede8fab6dc1d0c953556e5172e47866c4bed2` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:2bb3d3096b1ffa47ceef5433a6c4f5edaa75c3d18b98d1ba536b961442b952a1` |
| Guest signer | `sha256:68280b338b71f10a87588cd8b8582abce31428f767967a1eb62d3f80bcc0544c` |
| Protected sensor | `sha256:ea333a24a9c31bcee66d7250e22fcf2917f49f0dbe3bb4fb0915abed80db9616` |
| Fixture bundle | `sha256:4e1a741f3e2bded196c8153719947ffe3ce836255cc44423eeb393b75ed0ec02` |
| Signed-image manifest | `sha256:d70897db31bc98b83ea6797137dc281098e27d267843f359880c68c471485658` |
| Challenge | `sha256:23e473bb0bb71be1e07cb7120be39eb51953f121500e2cea8a1f91ca07b2fb78` |
| Run spec | `sha256:75b634ffc2f618a70a1c92159eee258f3fa6e9493859a0510943a50c2764e315` |
| Guest network evidence | `sha256:44658953c5853b55cad45a7d42ab9835ca8537f2f0141220bdd0ef5fc35be737` |
| Guest receipt | `sha256:e3578d4a482bc7737cfda96800e6229fdcf8c79b06e952f1c214a08ae12081cb` |
| Host packet/lifecycle evidence | `sha256:9ff73a3044edb0d9695ce3a14718d456dbbed6311accbbe78244fb9dd6dbee36` |
| Host receipt | `sha256:084e8f6235102d310e3f7c73b63d70660f2b6230eb4b21bc34583e160e4bf0cb` |
| Sanitized serial | `sha256:a56bce2d6a27a702fe95c6e43a1a091d2d38fefe4be7b65a50c852047b3db411` |
| Guest source / inert target | `192.0.2.2:51416` / `192.0.2.53:853` |
| Raw / matched / unexpected / forwarded frames | `1` / `1` / `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two clean signed-image builds were recursively byte-identical and passed the independent image
verifier. All eighteen earlier cases were rerun physically on this exact identity and every
complete case was independently verified locally. The restricted, gitignored sanitized archive has
SHA-256 `f80713db675015697d3bba976a9c5f62d939f2f29a01f4be02a0bd012f4d83d1`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. Nineteen of 38 cases pass on one exact identity. The backend cannot issue
package-execution authority. The next drop-accounting gate is `bpf_reservation_failure`.
