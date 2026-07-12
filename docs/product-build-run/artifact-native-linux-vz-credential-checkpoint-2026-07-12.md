# Artifact-Native Linux VZ Credential-Change Checkpoint

Date: 2026-07-12

Status: `credential_change` plus the six earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 31 of 38 cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Session-Escape Checkpoint](artifact-native-linux-vz-setsid-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The trusted root-owned sensor now observes its child dropping into the package sandbox before exec.
Three cgroup-filtered raw-tracepoint programs require exactly one `setgroups`, one `setgid`, and one
`setuid` syscall from the exact child PID. Live procfs independently requires all four UID and GID
values to equal 65534, no supplementary groups, the expected protected parent, and the calibrated
package cgroup. The unprivileged runner reports the same post-exec identity over a fixed inherited
descriptor and remains alive for bounded corroboration; that report is not detection evidence by
itself.

The canonical payload requires the exact
`fork -> setgroups -> setgid -> setuid -> exec -> exit` sequence, one child throughout, two
heartbeats, zero drops, complete teardown, and no truncation. Swift verified the guest receipt and
separately signed zero-frame host lifecycle receipt. Rust independently decoded the retained bytes,
rederived both claim sets, verified both signatures, and reproduced the complete-case binding.

| Binding or observation | Credential-change case |
| --- | --- |
| Backend identity | `sha256:d8b73a14c1d8603f15ebb39b0526beb1252d294b1c50f55b6df27b94e42e5684` |
| Signed host helper | `sha256:eb34cb82e5d63259463bedc7bfbbf73edf3dedf57e206dfd773663ce467d2ca2` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:8dc0d0fc16d6412653610a80c261b3a5bbf3e82075f104b2cbd7df8337054622` |
| Measured guest signer | `sha256:169e49ba06d3a3df02e7190d2e8d76960b4ae74e62b9f48ddbca15c9adcc2a67` |
| Measured sensor | `sha256:bb5b2817d550d9d71298d72360af49c1e34118a0484356403b33b820082d6fcf` |
| Measured inert runner | `sha256:0d25eb9ea08566c75bab3955fd2446924b75c4a94894c38638f90c2e257b252f` |
| Signed-image manifest | `sha256:491a0261c94404d22c9641ba06e3817bc362834bd5eb69aa689a74eab102923a` |
| Challenge | `sha256:a5807b0a2c7fb9db79bc5109261be50e21b9776871e6539c6185b7be835eda15` |
| Run spec | `sha256:61d4e90f6bc2e2b24ebc0f3a4f5291b37f0f9f7b33182724cfea845b160ff0e3` |
| Guest process evidence | `sha256:391a9856a0c86ed1d1b9b4cc502921367618c417fa9a3e2a61035e8e46f925af` |
| Guest receipt | `sha256:429be72b60f710bb0fdea6a0cb016605061c5b8b9c79892c271cb5244f52a673` |
| Host evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:cee55b6f3cdac6aeab6946cddb87cf512f654802e23645c13d3716aa37e5fd6e` |
| Sanitized serial | `sha256:ee22208784e30ff220e8eeb2902f1f9444e991cf67424e133205f2c6d5e6a4a6` |
| Raw/external frames | `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

## Same-identity rebaseline

Changing the measured runner, sensor, guest signer, initramfs, and host helper invalidated all six
older receipts for qualification. Fresh physical runs passed and were independently verified:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:82cb2ce914390e0b643e14594dcea1a20364b00d6f4bba77125687176279b842` | `sha256:d00193f33afc4c5fd92fd4f330c481b39cacea8be33aedf6f94c37e58988c36d` | `sha256:049a0c3525bc1a6ab26247d10ebaa3bf3e9a49ec37652a15321ac2f71b93b778` | `sha256:aa8c701c5f1a99a89ea86fe2dbfa7c5e16bdd756eb56dc840fc3adc47b0cf405` | `sha256:5e04a3ba754ce1291e51dc967ec44d8f19fdd9c79ffd19c50190e92b1f8ef494` | `sha256:4ed05a97c56cf163491df9a0d0b291c5529c7fe49d5f0212115345c897094089` |
| `reparenting` | `sha256:c47de5e76dfb8bd7418a301c15080d59364d04cef441011cc1b5e6e5c93d077d` | `sha256:0990c86a9172806d22bd644bfdc2238f29c2b19197f06db5eda08e409b6709f3` | `sha256:463a26c2411a11ebee427ca5b42fff236d3b58edb2815ca4c6eec5875b63aeb4` | `sha256:85bb262730dae681bb40efe922535e363a32a713820538cb7904b1b3e43666a3` | `sha256:59426d5ed5dded919308cfbceb2f084cae89bc88c89fc24696cd340a87ed652d` | `sha256:b625d5fba924ca5c39810d220b779d324e6109370f83b6dd1099cf47381c50e4` |
| `double_fork_daemonization` | `sha256:0aca431711e90131bb805526b7f0d84cd2c3224dd9b07d33e2cef0a745d3fe60` | `sha256:1d4beb6117c62493315ef4ab11b17fa03e239f32c68ae8c7a461d339a978891a` | `sha256:984453ddf96cf9a4eb1e287a9b2550a6719997e758bcba147e9c9ebfc1d507fc` | `sha256:0254c14055ede906c5388881054b60582057c385750949a1e321f62722eb8789` | `sha256:65ca1f3e51e849c4f21b5c067b1cfdfc464b363b75b4f7570f74eb91649ef42f` | `sha256:745a4a48077612d626418fe9e28d8163723ec8542a1c00daf356b4847df8f4a9` |
| `setsid_escape` | `sha256:12cbdc2eaa92bc032f6bc24a074977c60604e9fec29c08bf06f7ce21a62beb7d` | `sha256:d207e63c463690a22d7317446a08f824cb3fdb8fd2ce698f8e7eb93795636b15` | `sha256:9e7715bf76b881279d9a2d563d52dae8ed8fbda3eaea9e95902565420279d6a5` | `sha256:082f0083fe6478cb989d845bb28bddb7d0d595dc918ba670afb0c48f1b51ce01` | `sha256:2cfdcdaad8113aa584e5fc8e542562696b34139b9a55341cfe88200f1d04e537` | `sha256:92628e8d3044b705442bdb2e97ceb05258c951ea2b7cdd4a2176680f8e4aadf8` |
| `protected_open_read_write_rename_delete` | `sha256:8907b29c5e246146af9d6d161fe5eda7f7e281128f467889a1f2164fb971d011` | `sha256:c00407760fb3569203881ad4b8c79650599309ff655d3394d7f6b47e1f1bba87` | `sha256:e8ce93a2e21b5f45abf96ec9c5263b889db0e5233c19daa489984a9b3bb2484a` | `sha256:05beca6a121a9dd20d8e4c79f46a82218942cae6ecf36e47a21e5eaf580922d9` | `sha256:5445f90cd772b7518a688d0ea7b521059e489a0f649a1337b4f2d331de54d2b2` | `sha256:bcb3021dcb7c21ed76a28908db6915cc09034cef1420c589ff87d638e967b095` |
| `mmap_access` | `sha256:aa6c35708afa4d6a5ebe66855556022d4703abf649c5f20824f26b42502eb36f` | `sha256:d2e6d487f32fc549144be307c26a4493de0912b7dde687fa839d24cf2398b007` | `sha256:278594abf1cbbb89f5dd55f2bff560384d5cb6d40ce1580fc8562016aa3af2b6` | `sha256:91d224210847c89dee2ad799e024598dfc48698f1ce319e5a00fb23294f7abc9` | `sha256:eed987e50aed5ebef65d5a04d64031b0edab515c07cf77c8b9ac06b38417f6e6` | `sha256:799d6e182ca98073b80b8f9713fd2d7bcc4dec07ed41d50c58715f68f6eb380c` |

Two clean signed-image builds were recursively byte-identical and independently passed the image
verifier. The physical credential case and every rebaseline case passed on the first attempt.

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Seven of 38 cases pass on one exact identity. The backend
is not qualified and cannot issue package-execution authority. The next process-lineage gate is
dynamic-library load before network, fault, teardown-stress, platform, and isolation coverage.
