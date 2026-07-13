# Artifact-Native Linux VZ Package-Isolation Checkpoint

Date: 2026-07-12

Status: `all_protected_assets_denied` plus the thirty-two earlier physical cases pass on one exact
measured backend identity; the backend remains `candidate_unqualified` with 5 of 38 cases pending

## Outcome

The package-isolation gate proves that the unprivileged package fixture cannot read or write any of
the seven root-only execution-plane assets while protected process and lifecycle evidence remains
complete. The exact set is the capability probe, guest signing seed, guest signer, process sensor,
and three virtio-vsock kernel modules. This is an exact closed set derived from the canonical
initramfs layout, not a directory-enumeration claim.

The UID/GID 65534 fixture attempts `O_RDONLY` and `O_WRONLY` access to every exact path and returns
only a fixed-size count and denial bitmap through its protected report pipe. The root sensor does
not trust that report alone: it independently requires each path to be a root-owned regular file
with one link and its exact archive mode (`0700`, `0600`, or `0400`), requires the module directory
to be root-owned mode `0700`, binds the reporting PID to the expected parent, credentials, cgroup,
and BPF-observed fork/exec/exit sequence, and requires both seven-bit denial maps to be complete.
The canonical sensor configurations are identity-bound host inputs and compiled guest behavior,
not separate guest-readable files. Guest evidence remains in protected process memory and the
bounded pipe/vsock path until the host writes it, so there is no persistent guest evidence file to
add to or silently omit from this filesystem set.

Strict Rust and Swift decoders require all seven stable asset labels, both denial counts, healthy
zero-drop evidence, complete teardown, and the terminal
`access_denied_with_complete_evidence`. A generic block, partial denial set, changed label, corpus
classification, or normal observation-complete terminal cannot satisfy this case.

| Binding or observation | Final package-isolation case |
| --- | --- |
| Backend identity | `sha256:73e275c909c9cec50c908f20a7088244093288bc53ba7f5bcb00abc4491cb231` |
| Entitled signed host helper | `sha256:18aabc846da42fd56f78c99fb151b02fbc93e5c71cd2cf999cf06203150d9e6e` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:5d2b318a28d7a31a9c3acf4a56151caecb9eef22048a2e3376f5bdf4ea88ef59` |
| Guest signer | `sha256:c2e4ad0167360c0541814dcd1c4c9dd8d834abf6a3460e43a69cf984829acaaa` |
| Protected sensor | `sha256:1888030009504f9e382f669cab6dcd0f96e7de23c89d9e876b81b20c9290b60a` |
| Fixture child | `sha256:7e7a89c131266f020035f35787e8f052e6901b390deffb433a22ef85cf02c2f7` |
| Signed-image manifest | `sha256:a754f2a02d969b82dfb233f0eacb4fbba7d7442c410f4f409a0ecbe9211bcd03` |
| Challenge | `sha256:32e4730529a052ce942a60b86ee3f2a7a471951630681c8a132135d39be010fa` |
| Run spec | `sha256:e540b3e96c017b907ee1ff967d94c99d5920aa42e0fb157bdad21e6ae6983045` |
| Request frame | 5,153 bytes; `sha256:2f89222eec4b07dcd4bdc319465e65917374ca95ec0615f922ad45ab05e4555c` |
| Guest behavior evidence | `sha256:08f8ef8050eff9cdce26e834f6bfa9db7064131a8f7a7e0e55364595499e8ae7` |
| Guest receipt | `sha256:fd5c20f0573006d84c0fd285329d7c668aabe466ad4f55436d1c4959b0174886` |
| Host lifecycle evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:b048f637733a2ede251e90a8277c82ca2bebfd76b999b2287982a91efbbe9137` |
| Sanitized serial | `sha256:8de6e67a94855d58edd69b3eba3251cc63ae4ce466268a63a53fe490c4c8bfe8` |
| Protected reads / writes denied | `7 / 7` |
| Guest events / guest drops | `3 / 0` |
| Raw frames / host drops | `0 / 0` |
| VM stopped / clone destroyed | `true / true` |
| Execution authority / package execution / sync-back | `false / false / false` |

Two independent local image builds were byte-identical. The first physical diagnostic reached all
seven denials and produced a valid guest receipt but exposed that the generic Swift host-evidence
decoder had not admitted the already-defined access-denied terminal. That omission received a
regression test and fix; because the helper is measured, a new backend identity and all-new
challenges were generated before the final run.

All 33 implemented cases then ran physically on the final identity. All 99 downloaded request
inputs matched locally and every complete case passed the independent Rust verifier. The
restricted, gitignored inert evidence archive contains 294 files and has SHA-256
`8139a1a1860252fd547a72475e62294845589b87f445ebe9586251778eedabcb`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, restricted, unknown, or
malware package code ran. The backend cannot issue package-execution authority. The next closed
gate is `kernel_config_and_btf`, followed by `cgroup_v2`, `fanotify_permission`,
`bpf_program_types`, and `raw_frame_attachment`.
