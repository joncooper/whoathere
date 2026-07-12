# Artifact-Native Linux VZ Session-Escape Checkpoint

Date: 2026-07-12

Status: `setsid_escape` plus the five earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 32 of 38 cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Reparenting Checkpoint](artifact-native-linux-vz-reparenting-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The closed inert runner now records its inherited session and process-group identifiers, calls
`setsid`, and reports the resulting identifiers over a fixed inherited descriptor. That report is
corroboration input, not detection evidence by itself. The root-owned sensor independently proves
through live process state that the exact package child became both the new session leader and the
new process-group leader, changed from the inherited identifiers, retained all four UID/GID values
at 65534, remained under the calibrated package parent and cgroup, then exited successfully and was
reaped.

Protected tracepoint BPF independently requires exactly one fork, one exec, and one exit. The
canonical evidence binds those observations to the same PID and cgroup and inserts the corroborated
session transition between exec and exit. Both strict decoders require the exact
`fork -> exec -> setsid -> exit` sequence, `session_escape_count = 1`,
`session_target = new_session_leader`, two heartbeats, zero drops, complete teardown, and no
truncation. Swift verified the guest receipt and separately signed zero-frame host lifecycle
receipt. Rust then independently decoded the retained bytes, rederived both claim sets, verified
both signatures, and reproduced the complete-case binding.

| Binding or observation | Session-escape case |
| --- | --- |
| Backend identity | `sha256:30ddac31a0e0a2c273bee37c1b7af4fd376abdddc496cfaadffd7aa3248a46c8` |
| Signed host helper | `sha256:3085df77edcd04683b34c792a21d73129deeef5e1aee08a4640ac433f4e27837` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:49b5299ab2fcfe3c834cd8177eb5b1fe1a2e372257e394b94e6e407f1684c8ac` |
| Measured guest signer | `sha256:2f5c8f57cb083495481f2a429807f73b204455b0c63b14277fc3a05899fcf465` |
| Measured sensor | `sha256:40b2db74f2327b106143015337b70a4c6c45e4095e0a4b90c9e0451a1cb4fe9c` |
| Measured inert runner | `sha256:5538f9d3997e763dc9b704f71c22eee9cdda19d291240f0ccdde0852e368531e` |
| Signed-image manifest | `sha256:8a6cc79e94cf0d13cfd44a0bfb3939affb1652e48872912148026eb2f4c30bb4` |
| Challenge | `sha256:304a6f3fe991f64d6d43fd0c96a5075f93216c6b67e32ee1c34d6048d8279ce3` |
| Run spec | `sha256:d5294e9241bb5f062bc93c8c61bd5953b19482e25f96417d9dc3e911a9828413` |
| Guest process evidence | `sha256:d48ebdf0ffd5f6bd15650479d0f9279bb2d226fecb1b6e628c867d36a7165e0b` |
| Guest receipt | `sha256:592b4cfe3d2256088eab56f40f91cb65184c5d0e4dac670c93a666f4e28bb7f1` |
| Host evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:e5697087eebffa749674d9224f657ae923f9335cba04ca7c34aa53c401db369d` |
| Sanitized serial | `sha256:330af0156d8add38a13eadae8f2bb4e4a26b35b7b5d86b81ff84ab29d2cb2372` |
| Raw/external frames | `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

## Same-identity rebaseline

Changing the measured runner, sensor, guest signer, initramfs, and host helper invalidated the five
older case receipts for qualification. Fresh physical runs of all five passed and were independently
verified against the final identity:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:ca66d95c479620e71f2fff4632a3eda7f8751584f030e05f0c1c1a729383d2ef` | `sha256:f8a3ea5d67aaa10ac0c4c08c21657654a1628005f74fa43970f05b91de919581` | `sha256:460e68e47069e6300f663c21c740d59c5589949287ae1cc317b040c80a57a735` | `sha256:50139f4ef166cb7b59735edeee9e7bfa87c95e090e5d68348d904e889694c819` | `sha256:3ba130a7068758c82445097817e802c574683a72028f3a5b0ac2fc5c86dc4737` | `sha256:bacfb9a97ac05529ea386ea51ada14df72793830081cc846c72c5169dca83f96` |
| `reparenting` | `sha256:80037443c26a1092131c05f163300927bbc787e26e1037753c6d54374448a3e6` | `sha256:bcada600b39e5a6b44faf804d2f99e3af55bfd2a8f8d2ec1194074cbfd677664` | `sha256:ca50359f893464a80434a1920c98f4338e2a23c1e3ffc56115d21044dc7bb6cc` | `sha256:7dad1e1d481ac7c4c30d8b42c6659531071fb44f7fea3a242c1e91997fb95936` | `sha256:234fbf4e81e02199a1c09aa30c063eca254a1e9a622ce5087a010ef68ae25a59` | `sha256:c53a1e4d1e33d296393bd585ae8bfd67879ae27f5bacfbb5aa10ca2876721758` |
| `double_fork_daemonization` | `sha256:74ec5ae7d4827ee1317a8267db74c5f45f04f84f1bf167587083faa8c0e0fb26` | `sha256:9a770d7310e4ca8d25bdcb217fde5d323ce2ba0eb06012d5eb99042ed7fc7e1a` | `sha256:2986294357c7d41bad0421e4cf4a9b7d89d2d2842ba3636e457580def004cc08` | `sha256:bfda027e9468edf5249f705793e39146268fc9fafcb8f0d29e7c6b016a4a39e2` | `sha256:cded8a463d2918f468c990ee4cf3ab4021b84e98feeb00dce3bac7f59f8e9750` | `sha256:40234d638f4c61e456e2711a8a1eb6e4e36bcb7a38af978a9dba51228b880c77` |
| `protected_open_read_write_rename_delete` | `sha256:4c8a186ebdc97332352d203ce3d66cfc83466c7a1e51401dad17651432bc7bb2` | `sha256:d7f5bac6c85748d4c48f827d3756d08d76a7c7e9c571c381c3302f714d123093` | `sha256:f39831445ccfb9023f87f6a997d12491d3272870dee99dbfc4f3664e674e6c40` | `sha256:ee4fddeeee4c66eb58d2861a63a8eeb5d33f26183714f20eb4a74443b4512ef8` | `sha256:cfeebdfb559329fd8749f6680ba7338e95004a7ff2f5d370e85436123fb180e1` | `sha256:e62eeb30c349d4835a39b69908104728c9c935dc093fe4a1a070a6c6bf7baed4` |
| `mmap_access` | `sha256:f4c1f9b36cd2a0682d15f8c5241465045137b6458fd51cf34d7ad0700424c919` | `sha256:1bdfc940124c11cfbeeb7a0992ae12df45f62683acf3e3ec53f5dad837a21c66` | `sha256:ad989a0722738bfbbd08239d0833b6537f702adcc4a8577b9c0b0378afd3b69b` | `sha256:dc12e2fe7aef90e894ed1336baa6ca99eec8e96e553597fd125df9381b573318` | `sha256:4cbbca1b335645ddf7788a80ddf3c477fd2581cd93550c7b1ec7cde9cd1cc81e` | `sha256:a587ea4ecd5eee09e8c3da6de1b4d03f250971103cae33cbed43757efef293ad` |

Two final signed-image builds were recursively byte-identical and independently passed the image
verifier. One earlier physical draft failed closed before issuing a receipt because the minimal
guest legitimately inherited session and process-group identifiers of zero. The final sensor
accepts zero only as an inherited baseline, still requires nonnegative syscall results, and requires
the child PID to become the distinct live session and process-group leader before evidence can be
emitted.

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Six of 38 cases pass on one exact identity. The backend is
not qualified and cannot issue package-execution authority. The next process-lineage gates are
credential change and dynamic-library load before network, fault, teardown-stress, platform, and
isolation coverage.
