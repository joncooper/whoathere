# Artifact-Native Linux VZ Dynamic-Library Checkpoint

Date: 2026-07-12

Status: `dynamic_library_load` plus the seven earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 30 of 38 cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Credential-Change Checkpoint](artifact-native-linux-vz-credential-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The closed inert runner now execs a dedicated dynamically linked aarch64 musl driver. The driver
opens the exact measured `/whoathere/dynamic-fixture-library.so` with `dlopen`, resolves and calls a
fixed marker function with `dlsym`, reports the marker over a fixed inherited descriptor, remains
alive for bounded corroboration, and unloads the library. The descriptor report proves the fixture
completed, but it is not detection evidence by itself.

The root-owned sensor independently requires a fanotify `FAN_OPEN` event for that exact protected
library and an executable `r-xp` mapping for the exact path in the live child process. It also
requires the exact child credentials and cgroup, one fork, two execs, one exit, strict ordering,
complete reaping, two healthy heartbeats, zero drops, and no truncation. The canonical payload binds
the measured target `measured_inert_fixture_library` into the exact
`fork -> exec -> dynamic_library_load -> exit` sequence. Strict Swift and Rust decoders reject a
forged target or changed event shape.

The signed fixture-bundle descriptor binds the static launcher, dynamic driver, and shared object.
The guest signer rehashes all three files and the canonical descriptor before it will run the case.
The image verifier also requires the driver to be a stripped dynamically linked aarch64 executable
using `/lib/ld-musl-aarch64.so.1`, and the fixture to be a distinct stripped aarch64 shared object.

Swift verified the guest receipt and separately signed zero-frame host lifecycle receipt. Rust
independently decoded the retained bytes, rederived both claim sets, verified both signatures, and
reproduced the complete-case binding.

| Binding or observation | Dynamic-library case |
| --- | --- |
| Backend identity | `sha256:d9c49ec7cde5837d55b5fe21248e7831f5e39295eec6ccfeb6bc8b2b94b2df06` |
| Signed host helper | `sha256:a188cce3dfdbe2148c1bfe7fb9f17b737a4beb474c271d4eaae97f4bb9cbc983` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:f5cdb448856a54a0fe76c2dd4b0d8845b3a4573fed84f878867f7831ef34891e` |
| Measured guest signer | `sha256:af8f6c579c60511934e117580ccc46520ca6d9383bf276bcc61c623620662f70` |
| Measured sensor | `sha256:5583ccaa40f313533c3ff682d12976e3e4b076cfecaf13949072ea61deedb7dc` |
| Measured fixture bundle | `sha256:92a54f80fd833973308756f97e311f2eaa2e191bae693ac580789f44aadb9913` |
| Dynamic driver | `sha256:d8d65324f3ca9810bf621e7788d8dceac14de1aa55519601796a89827a101e08` |
| Dynamic fixture library | `sha256:89f23d48e4c92287a928afc617fdc6d5a08939f372cd35d43dd710ba63bb77a6` |
| Signed-image manifest | `sha256:2e885fda5d2d8f32c85007dcc09acbeba44bb93d1e0f0f302aa9e3ff14b4302d` |
| Challenge | `sha256:fa52e036f2d3e5b019b0600fff631d9c4472c317b2683bc3eb1c24c51856a02c` |
| Run spec | `sha256:cc45e1c045d44f2bf8d4d5b5b2275064529f3016473b1b401af39b2f10b62cfa` |
| Guest process evidence | `sha256:2fabc5ab449937bea67d5a56211f5b1e226d89aec44ad8af93ef0cbf05cccc41` |
| Guest receipt | `sha256:2172f5816a480ec1562fcbaa4c186c25a836a51edb1fa3bdf53a588e5fbdf313` |
| Host evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:e532214c9ebbf017e0be07a775bc7dda40c3035bf46fcf7e6b889b790d682006` |
| Sanitized serial | `sha256:04176e88c54a2d10b8bb1742396eb750a72373ba496d2db611cd11f683ed0a5e` |
| Raw/external frames | `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

## Same-identity rebaseline

Changing the measured fixture bundle, sensor, guest signer, initramfs, and host helper invalidated
all seven older receipts for qualification. Fresh physical runs passed and were independently
verified against the final identity:

| Case | Challenge | Run spec | Guest evidence | Guest receipt | Host receipt | Sanitized serial |
| --- | --- | --- | --- | --- | --- | --- |
| `fork_exec_exit` | `sha256:f06cb7b6a2d67491bf26703bf46ab62a10c9e2939d0988bbf10148da73d7fe69` | `sha256:021fa6983c60bc7bb2fcd560a8a8838a33ee287bad64268d737bbf851646e9f3` | `sha256:2b54490fe95d3cb93ecc660cc558dd8888a8a179c86b0b1276df8447d5314ab8` | `sha256:8cdb20fec141defcf57328c6b024b4ee614e3ed13f4e4c5dec87c9887e1112be` | `sha256:aa9ce19748a50b5d68c5eac4302b0b55789e6ae373c9a987b194162040ba60bf` | `sha256:ae50eef862453b34bcfba0c943f1812db75b1983c15617a7868a565aea96bc4a` |
| `protected_open_read_write_rename_delete` | `sha256:0097cba0394f1fcb9c155214392ed41a97e8a2b626e1b70e4ecacf59394bfbf7` | `sha256:19e0b9e0d0657c24ef944c9fc0bd44e1e3c11cc59caa6bf131c157e1fd334339` | `sha256:6be8597e5f2beeccf2ea9cce1b48aebbd142b88fe4e5d54f876dac042b98189c` | `sha256:76067952e12a4095a2e56262634b6a21af1922e5948256fabec97ac9d040aa95` | `sha256:7ea68797e4d7d6be5bfdc7544baa510eb47e904bd8d407db39e1c2f492fb3c0c` | `sha256:7b88881c05517b84292706a4477addb91c88d90607b7fd846f443a0cc0030a09` |
| `mmap_access` | `sha256:e5d2975d44eb5d090bc95d2276947e1d00d106668c3877533761f23418dd3f94` | `sha256:b714a47013c13a8487de171d7e59b23cccec808b167a0e83a328084e627cd176` | `sha256:b45efcd90f354c977fa97ce7d0fedf92c948c22c460f8a76888dfdad5159aab1` | `sha256:d5b007da638aa8d6c6a0e38a59a15c4e8bbccccede2688fd63508782a6c15bfa` | `sha256:fd17a324383f53ebb6706dba0a70247fdca8adb59ffcfd5910589c69b9318e4b` | `sha256:47de81f89e3e84166c23fca062765761a3071119995e689c06d3d9ff99114c5f` |
| `double_fork_daemonization` | `sha256:cb6e6c5835bf65007937f6929b0ad84f2105de7e549daeb0e9cc5e828b08b635` | `sha256:db1fd98293244d6cbe5d03f945ed5b138c403343488a6091acf422685c02c2e6` | `sha256:6ed1e921f7194a603a4280ef241f4a12702515ec42077f0e2366db1f5e8151d4` | `sha256:f77b02d6246e470c2fb1050c1c6be77f3b97053482197e8d241c1b13c15f1191` | `sha256:db22553a3a55ec3afd97848a95385d757d826fbcfd4ab8b8d566ae96357d7326` | `sha256:97f9a9552062ed3ca228029fe189c144e85f11b73cb870e88caa51862aca2a6f` |
| `reparenting` | `sha256:ada1fbf20eb59e4477b0d30152f94fee208992dffaa89ac22c8a33a33f3c17c7` | `sha256:4bc67734600530338166410a40f1ee97037e20c4c80822a6a7a1474a37925177` | `sha256:9fc15d40e58faf3b0ee9692e9d211383d4f209e81e906d0f545b866a448dc71a` | `sha256:8dc9397979b51c15420b4b3d609a992378211683a50c79c4859d50c29d5f262c` | `sha256:e5679a25ec96cc265e89c4ee0051868932aa14124bbc8b730d98f63aeb9c0720` | `sha256:37b23f9af38127cf095c3c1c64ea6647f4342b6f93bbf64e0e8f0364d98f0f16` |
| `setsid_escape` | `sha256:0ad34b857344d149e9af3a84eb02c9704910e2c6104a3063a2fd6115ee50d0e4` | `sha256:10c732ef42ca9afb6bc987d4e5414613d812794fc3c455114622972f42340c14` | `sha256:b567b6822ea9db2ddfbce875ef4500aa6ab801cfd1d8689995eb104a0ff445ec` | `sha256:32692e2e408b33dbbfb811e050a0565e3aa69f5133e243d9a58cf6722ab0abc9` | `sha256:d67c6092e2d7d8ed58ca441e668310b2031c24792617996d4e700314929d5a6f` | `sha256:67d2f23ab3bf1d6221c730c8f6f2ca27e591a5f75228dc7443a3d7ccca099ce9` |
| `credential_change` | `sha256:742c3bf293a904fbb86ae91f263eeae110ba1b347a2cfc5ed888de59d7ac7eea` | `sha256:fdc065b6ddfa78e40b83a159400db981305ec77078570ee1ab8419d7e808644e` | `sha256:22c9d5b214b8cd5c0f99e9a0022cd12dc0d223a1a21878db7838ff4d168304df` | `sha256:ac6cf97f93a7b24ced2949807971510ffc225fbe029f3abb102c8e7d56cfd064` | `sha256:f0c5f3e0f815fd490960a82fb10075098efd3b17ddfbc153b9f0e5d71726c093` | `sha256:a1c985c2c1c2604e5c81767f1ffa0c193204a36e796a11c34a46fa60ca424212` |

Two clean signed-image builds were recursively byte-identical and independently passed the image
verifier. All eight fresh physical receipts passed the independent complete-case verifier. The
first physical dynamic-library VM run itself passed and emitted complete receipts; an outer zsh
inspection wrapper then rejected its use of the reserved variable name `status`. Direct validation
of the canonical helper result and both receipts confirmed the VM case exited zero, so no rerun or
receipt substitution was needed.

## Boundary and next gate

This remains protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran. Eight of 38 cases pass on one exact identity. The backend
is not qualified and cannot issue package-execution authority. The next gates are the closed
network cases, followed by fault, teardown-stress, platform, and isolation coverage.
