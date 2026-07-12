# Artifact-Native Linux VZ Double-Fork Checkpoint

Date: 2026-07-12

Status: `double_fork_daemonization` plus the three earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 34 of 38 cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [mmap Checkpoint](artifact-native-linux-vz-mmap-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The closed inert runner now performs a real double-fork daemonization sequence as UID/GID 65534:
the measured launcher forks, the intermediate process creates a new session, the intermediate forks
the daemon, both ancestors exit, and the daemon exits after a bounded pause. The root-owned sensor
acts as a child subreaper and fails closed unless it reaps all three package processes with successful
status and no remaining descendants.

Raw tracepoint BPF, filtered to the calibrated package cgroup, independently requires exactly three
fork observations, one exec, and three exits. The canonical evidence binds the launcher exec PID,
the last fork's intermediate actor and daemon subject PIDs, the final daemon exit PID, strict kernel
timestamp order, three protected reaps, two heartbeats, zero drops, complete teardown, and no
truncation. The fixture also reconfirms that UID 65534 cannot read or write the root-only sensor.

Swift verified the guest signature, the separately signed zero-frame host lifecycle evidence, and
the complete case. Rust then independently decoded the retained serial and evidence bytes, rederived
the claims, verified both signatures, and reproduced the binding:

| Binding or observation | Double-fork case |
| --- | --- |
| Backend identity | `sha256:1e6ade0b6958bf053eed53af956d0df544681a2a3b603c8ec0a273c46f1cf87a` |
| Signed host helper | `sha256:9b98a106ef94dbc20e46ab56dc5416f6b436ea2976a77a2e15484e534d1b379e` |
| Signed initramfs | `sha256:3749a702245ea8e7c782fd254077975daa861b16da6fa1553fc25451a3e6f937` |
| Measured guest signer | `sha256:3faa4adc941b7bedba92cb8a09c6f04e2313f187f1b014e9176972fb97a294b7` |
| Measured sensor | `sha256:17a550e7f5dafa8c193c4e461ead25a34f0160d4be54208e24b20bddc147a4df` |
| Measured inert runner | `sha256:34ec67b2239c7bb8a8aab9c836743c53679dad16c8564e8ced15c84df7f8f921` |
| Challenge | `sha256:b7a8e30a9be0df7498309b209ce440c3bb71ff66483b8847b45d0294961bbd49` |
| Run spec | `sha256:30dc7d308eb79b27aa6a253e74127b27608e5a45e021280380d6761df9a23888` |
| Guest process evidence | `sha256:51ebfc865b1699969f664bd3a43576e465189f2808cde1609a543e3dd3a16bac` |
| Guest receipt | `sha256:d66b30be618562e8bc043d8779173aa35c7bf113140c727cf39560646856d947` |
| Host evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:baefe18fe98d5eb07643a95807c5175d3b1167e23efad4b7b77da68e46079698` |
| Sanitized serial | `sha256:dc22d8c31d5eaeb02f02b25033f26d985c60be7da42dbe8e0f13133428a53c4d` |
| Raw/external frames | `0` / `0` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

## Same-identity rebaseline

Adding the lifecycle behavior changed the runner, sensor, guest signer, signed initramfs, host helper,
and therefore the backend identity. No older receipt was counted. Fresh physical requests for all
three earlier cases passed and were independently verified against
`sha256:1e6ade0b6958bf053eed53af956d0df544681a2a3b603c8ec0a273c46f1cf87a`:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt |
| --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:52e1e7ec0c91185b58d31be99f02ecf071574f988a061de341b4cceed3c2bd6c` | `sha256:44a780cf0655cc9520e7296cca1652a2f1c8153755c8e27ec209432a869ea7df` | `sha256:6af40508fea4b46d39851f3303b735491e303dc1b84fc7e53d7e02c1772214c4` | `sha256:af00219c1d5f659b6f4ae4a0f95e9a6856be5584b3923319f6a2c6a8bdfdeb6b` | `sha256:5af94350bc82df570883a9f1e69159c1a757c147cb0014157660e59cc0e44551` |
| `protected_open_read_write_rename_delete` | `sha256:fb5dbe14740a5161ee8d72e246f8673206dd8cf4842359f4ea158501f19ba16d` | `sha256:83dbc68b695d62d859780e3d1bfae87d4a9417a34ee2362ae0df82e327bf2e07` | `sha256:2c8d45d91b7ec471cf30354114242fa6f44f269648bf41fb300db546e1ebbbf5` | `sha256:ef3dc61ef8443630183c3b739fb1ec3f258b45757b2921041b6b2eccd51a8f3f` | `sha256:f2c478f0feac00128a9e3c5f77e6a13d4000d09344d9a42a8b8d8b8f15c24b6d` |
| `mmap_access` | `sha256:8b29d0b657a2f03df72a1ee547575c40df485f34c146da4e6e928258b298eea0` | `sha256:0fd01b790efeae68b25d82669f396a01280d0bac9c8d4d01c2c7a4aa43f6a745` | `sha256:ab4b25d83e9e2f4dd2547a279d5df6a2f8232d42ff7b5d00ed52e8ba96b067ca` | `sha256:23a3ef6e0b64951b9f245b577d536cbb50a45e7b500b8388031e0de67663d9c2` | `sha256:3d4df7d44747e41625fd79cc71d080632c2908d5491f48e813487d8df72cc47d` |

Two complete signed-image builds were recursively byte-identical and independently passed the
signed-image verifier before transfer.

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. The fixture is cooperative, repository-owned inert code;
the behavior-specific upgrade comes from the protected BPF counts, PID bindings, signed evidence,
and subreaper teardown rather than from the fixture's case label.

Four of 38 cases pass on one exact identity. The backend is not qualified and cannot issue package
execution authority. The next process-lineage gates are reparenting, session escape, credential
change, and dynamic-library load before network, fault, teardown-stress, platform, and isolation
coverage.
