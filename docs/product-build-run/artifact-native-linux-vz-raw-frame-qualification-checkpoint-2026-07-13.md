# Artifact-Native Linux VZ Raw-Frame and Qualification Checkpoint

Date: 2026-07-13

Status: all 38 authenticated inert conformance cases pass physically on one exact measured backend;
the canonical aggregate is `complete_inert_conformance_matrix_verified`

## Outcome

The final `raw_frame_attachment` gate now proves the actual macOS
`VZFileHandleNetworkDeviceAttachment` data path rather than inferring it from VM readiness. The
UID/GID 65534 fixture binds `192.0.2.2`, sends the exact 16-byte `WHOATHERE_RAW_V1` UDP marker to
the isolated documentation sinkhole at `192.0.2.1:40553`, and remains alive long enough for the
protected guest sensor to bind its socket inode and ephemeral source port.

Guest evidence contains exactly one ordered fork, exec, `sendto`, and exit sequence for the
measured cgroup, with zero dropped events and complete descendant teardown. The host attachment
independently receives exactly one Ethernet/IPv4/UDP frame. Its strict parser binds the source and
target MAC addresses, documentation-only IPv4 tuple, guest-reported source port, fixed target
port, IP and transport checksums, datagram length, and exact marker bytes. There is no forwarding
path. Extra, malformed, rebound, or missing frames fail the case.

The physical case ran on an approved disposable Apple Silicon lab host because virtualization is
not exposed to the local Codex execution context. A one-use host evidence key was generated on the
lab host; its private seed was never exported. No package artifact, package manager, malware,
live C2, second stage, root disk, sync-back path, or external guest route was present.

| Binding or observation | Final raw-frame case |
| --- | --- |
| Candidate backend identity | `sha256:f610a600fd2654cff2ec8979c0e4e27b1ccdd3aededcc5d4c2bde5eefc5b8c71` |
| Entitled signed host helper | `sha256:99390c747a6720f5e5bb0b3fa6e9e020b4203fb158713e65212acc9bb1e24e91` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:925f150d3faa7f036245391ce2c80a2f5524c13f77eea68de8a6a80c423f3b12` |
| Guest signer | `sha256:71a68545f1edafa5fd85ad1785bc538327a2e4b67deb09d93c3038b39b8487f3` |
| Protected sensor | `sha256:d1edfce7fdba9bccdc1cbc313d469bcc52c8eb1a070732b571cccaa44ce7b3da` |
| Fixture child | `sha256:ba702459ea985d2234ba0a53bd0ea65d1490f582bb8b7b4ed8f49a9a6e670d0b` |
| Process-fixture bundle | `sha256:eccbc1264292338b11f26a5c85dc4c32a2abffa200051d3b0d670d4175a789c3` |
| Signed-image manifest | `sha256:51e93172360a0d54d27929c3bd8ebcf6d8e502e5526a59c9de934c997dde8ec1` |
| Challenge | `sha256:512c3e3e99738928f7aaf0a42cd78e5130c88454d08328274df7e41b44c0b4c3` |
| Run spec | `sha256:f22f5da7e431425150a8b661a4258cadec78ea72dd3800abf6b578a4282dbe65` |
| Request frame | 5,081 bytes; `sha256:3c7596379f710fefa4ef2c74db946327cbc5cdd7846aeb6544283a2443a0162c` |
| Guest network evidence | `sha256:abf2acfc2f88e471e5df61598dd5ca490783f6bb2abce1f2c14a24714d20c684` |
| Guest receipt | `sha256:8e18248f0c9191fdb29cd805b37ec95eec718e93d23554139c69f20535889fbb` |
| Host network/lifecycle evidence | `sha256:42d4a7e856ac68db0f43719adb3c39652c33d088ebb9cf1a4fa059d4ccf2d9df` |
| Host receipt | `sha256:56e628dd3345f335dbe07a0a9e1dd0cd5c11ccfced53f040148901e7cb53a41e` |
| Sanitized serial | `sha256:dffcf411e97e839a22bc2e267a442af6acf5ad8f40728a4e34e90d4b7b60f27c` |
| Guest events / guest drops | `4 / 0` |
| Raw / matched / unexpected / dropped frames | `1 / 1 / 0 / 0` |
| Source / target | `192.0.2.2:<ephemeral> -> 192.0.2.1:40553` |
| IP / transport checksum validation | `true / true` |
| VM stopped / clone destroyed | `true / true` |
| External frames forwarded | `0` |
| Execution authority / package execution / sync-back | `false / false / false` |

Two independent signed-image builds were byte-identical and both passed the signed-image verifier.
The raw-frame case then passed both the Swift physical harness and the independent Rust guest and
complete-case verifiers.

## Complete-matrix aggregation

All 38 closed inert cases were regenerated from the final candidate identity and run physically on
that exact image/helper/key binding. Every harness result passed, and the independent Rust
complete-case verifier revalidated all 38 downloaded guest/host evidence sets and receipts.

The aggregate qualifier re-verifies the cases in one process and rejects an omitted or duplicate
case, mixed backend or telemetry requirements, reused challenge, reused run spec, reused clone, or
any execution authority. Swift independently decoded the resulting canonical record and obtained
the same digests:

| Qualification binding | Value |
| --- | --- |
| Qualification state | `complete_inert_conformance_matrix_verified` |
| Case count | `38` |
| Telemetry requirements | `sha256:3ff8c862243232fbc48ec91d5926e587bf9817f678853d02d9730cde2c464946` |
| Conformance evidence set | `sha256:baa3f1849c70d2faea4e2855ee184b32e34f1df602bdf4e2fa57a1a9611d35c0` |
| Qualified backend record | `sha256:fed9ddb696432fa40ce20959b366235f5b7c1b06fd1dedb413ded4f5916734b1` |
| Clone policy | `one_unique_clone_per_case_destroyed` |
| Execution eligibility | `typed_package_scenario_authority_request_only` |
| Execution authority issued | `false` |
| Sync-back policy | `structurally_absent` |

The gitignored sanitized request/evidence snapshot contains 415 files. Its archive SHA-256 is
`a34ad30e77cd41656c9ad8de98d9609fa364c3cd48a28556aad286b5b26c44a4`.

The full Rust workspace suite including doc tests, all 186 Swift tests, Cargo formatting and strict
Clippy, the deterministic 38-case fixture contract, strict static aarch64-musl image builds, the
package-risk and scanner-integration smokes, the real-world attack harness, and the controlled
actual-malware harness self-test all passed. No restricted sample was opened or executed.

## Product boundary and next gate

This closes the current telemetry-backend qualification gate. It does not show that WhoaThere can
detect a malicious npm or PyPI artifact, and it does not improve the July known-malware score by
itself. The product remains useful today as a fail-closed local containment and admission preview,
not yet as a trustworthy package-malware verdict engine.

The next gate is artifact-native detection: connect normalized npm, wheel, and sdist bytes to
deterministic static findings, AI code review, and typed install/import/entry-point/lifecycle
scenarios on this qualified sensor foundation. Then rerun the eleven known malicious samples,
balanced benign controls, and a held-out malicious set. The known corpus must reach 11 of 11 with
package-specific evidence before broader detection usefulness is claimed.
