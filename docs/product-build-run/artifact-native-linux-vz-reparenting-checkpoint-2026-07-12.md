# Artifact-Native Linux VZ Reparenting Checkpoint

Date: 2026-07-12

Status: `reparenting` plus the four earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 33 of 38 cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Double-Fork Checkpoint](artifact-native-linux-vz-double-fork-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The closed inert runner now forks one child, reports that PID over a fixed inherited descriptor,
exits, and leaves the child alive for a bounded window. The report is not itself counted as a
detection. The root-owned sensor accepts it only after independently proving through live procfs
that the child has all four UID/GID values set to 65534, remains in the calibrated package cgroup,
and has changed parent to the protected child subreaper. The sensor then requires the exact child PID
to exit successfully, reaps it, and proves there are no remaining descendants.

Raw tracepoint BPF independently requires exactly two forks, one exec, and two exits. The canonical
evidence binds the launcher exec, launcher-to-child fork, protected-subreaper-to-child reparent
observation, child exit, strict observation order, two protected reaps, two heartbeats, zero drops,
complete teardown, and no truncation. Swift verified the guest receipt and separately signed
zero-frame host lifecycle receipt. Rust then independently decoded the retained bytes, rederived the
claims, verified both signatures, and reproduced the complete-case binding.

| Binding or observation | Reparenting case |
| --- | --- |
| Backend identity | `sha256:4909f44c37c42e19fc16ccd8487a4077ff35ffe62f0920abb00b0e1a76a68c74` |
| Signed host helper | `sha256:c26683eb1d511995c6d0319dc2725c2a4fc516f78ab4987b69f4dd05dc2650ff` |
| Signed initramfs | `sha256:2b58fe0310a0e939422d194648ccbfe0d18b14ae59fb7faef63cc5cf18d6958a` |
| Measured guest signer | `sha256:d300e3259730558acf594b603cb49df5f2af20d856157467233e06af41c373fd` |
| Measured sensor | `sha256:d97f6d94c71326e8cdbcee666122b4b45628a9774e1fd45380c8e1e3f29a174e` |
| Measured inert runner | `sha256:bbb29b6c849804263974a59e996ba58e30f29f807e3122ff46476d5e8cee0223` |
| Challenge | `sha256:287f09ce88ff83fa805749859688b418d610132b643c17ba2859873b00bace3d` |
| Run spec | `sha256:af16d32375bb3c41aa4cd2b85fa9d8a6dce298fa8d9024b97e11245af810dd8e` |
| Guest process evidence | `sha256:15733da2d58a993f14cda2ebc90458ea919427d48fc65d8ee63eb172ecdb8901` |
| Guest receipt | `sha256:b16154be325d2268c030d7046ae78790904ca6946dcefd11504cdaf7103a88fe` |
| Host evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:495bcbfe7b2c395a7d7457e00a940230ebc4d87acff63ab50c3b2a6ddcbce827` |
| Sanitized serial | `sha256:3300b64bc30a84e38cb779eafdfc9e2fcacce6ee1949a5ca064ca4b2a3ecb3cb` |
| Raw/external frames | `0` / `0` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

## Same-identity rebaseline

Changing the measured runner, sensor, guest signer, initramfs, and host helper invalidated every
older case receipt for qualification. Fresh runs of all four earlier cases passed physically and
were independently verified against the final identity:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt |
| --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:2d7bfff4fac04ef941e57018a0ee0d7581def7f8b15d4a4a490e26d8c124dc9f` | `sha256:4a917c1d7edda238076fbe31d5734ee75b263b73dd8064efa514a543c9931375` | `sha256:b3c8dbc0d9120d61f7242be099d57bd32b290fcdaea03626caae652e5df919d6` | `sha256:f4aaa7023bbfa98c59bd56f51683461fe010272bce0f191d4e456072b37d4bbc` | `sha256:0a703f020c15995cc85efc2a08099b2c01406b0a7fe925bd46789a104ebbceeb` |
| `double_fork_daemonization` | `sha256:d956e51d20336a242f8130a36a8a9f5bb0f2a36a9f0947b68c9034480e32a1e8` | `sha256:84b45747e19bea65228ea32443c3d73f0959d464cc7dc9f039cef91bea428afc` | `sha256:5bee33d20411f7e9c6ffa54afd6b807b40608e0de83e1b202b41d8fcdcd3d4a4` | `sha256:f50ecf8c4ac1c9529196365438173f5362d4cfa66c90cd1a99554b722b216152` | `sha256:c585b84eb828a1493ce9c26a8f57b7d473c2d62c420dadcbaca011bfd9a68242` |
| `protected_open_read_write_rename_delete` | `sha256:a204e975ae47e64620564f51b2cbec00ef800e3b5485fbf9232b1e65f9c359bd` | `sha256:40aaa7c30fdc6e351474bf01f32c84199e329ce3f8dec9b2edf8fe5ee861186e` | `sha256:0cbe02e1634e8ac26d62b289a1cb63d6d3ff496b18ddbfdc3e0635413a19f0c7` | `sha256:506bf62081cc8677fc28360a3615db2596fcffa52bfcf1d0787c564a3767a367` | `sha256:da21eb450ed061c013ee81c88825ab87732ccb049f2402f87e0b4f824ae09c4f` |
| `mmap_access` | `sha256:37eb8194bd9581c51dbbeffb0de2c4799b13c9c57648d79d87962fee9b4e3eb1` | `sha256:fefd87cff19677ef0322fe135aba1c5ca1f63a7f0f6f77349ceedaabc4ea963d` | `sha256:e2c5821b749492ef61821a0c72719073b822933247ea8a110e07bf7290e21e03` | `sha256:7a464aa786043c34f7c8df6674916109962f0f1f19d1fdb55a480f87ca83df88` | `sha256:2fbc59c7a8435941d35e8d88289520fefa30d6e1255bda4a3adfaac6037ecf9f` |

Two final signed-image builds were recursively byte-identical and independently passed the image
verifier. Two earlier draft attempts produced no receipts: the first exposed insufficient failure
diagnostics; the second proved every reparenting observation correct and identified an overlapping
legacy-case validator. The final guard is case-exclusive and retains the bounded diagnostic.

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Five of 38 cases pass on one exact identity. The backend is
not qualified and cannot issue package-execution authority. The next process-lineage gates are
session escape, credential change, and dynamic-library load before network, fault, teardown-stress,
platform, and isolation coverage.
