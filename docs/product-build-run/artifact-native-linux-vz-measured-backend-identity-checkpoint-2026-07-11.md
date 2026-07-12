# Artifact-Native Linux VZ Measured Backend-Identity Checkpoint

Date: 2026-07-11

Status: the physical inert backend now has a canonical, independently validated
`candidate_unqualified` identity binding the measured kernel BTF, image, actual signed host helper,
sensor configurations, package UID/GID, and fresh evidence public keys; private-key provisioning,
challenge delivery, and live receipt signing remain pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Ordered Process-Evidence Checkpoint](artifact-native-linux-vz-ordered-process-evidence-checkpoint-2026-07-11.md)
- [Unqualified Backend Checkpoint](artifact-native-linux-vz-unqualified-backend-checkpoint-2026-07-11.md)

## Outcome

An inert physical boot measured `/sys/kernel/btf/vmlinux` for the exact pinned kernel as
`sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb`.
That value is now an exact required serial marker, a pinned image-manifest v5 field, and a strict
independent-verifier requirement. Future boots fail if BTF is merely present but its bytes differ.

Canonical guest-sensor, host-packet-sensor, and structurally absent root-disk records are now
tracked. A dedicated key generator created fresh guest and host Ed25519 pairs inside the gitignored
`0700` evidence-key directory with `0600` files. Seeds were not printed, transferred to the physical
host, or placed in tracked files.

The identity builder consumed the verified v5 manifest, the actual signed helper that performed the
physical run, both public keys, the three canonical configuration records, and the canonical
protected-telemetry requirements. It produced a canonical
`whoathere.macos_linux_vz_telemetry_backend_identity.v1` record with
`qualification_state=candidate_unqualified`, UID/GID 65534, and no execution authority:

`sha256:023d167e6e13aad423be13d0a1df6e205a9eb55d95d8b828426961d4ede7a627`

## Principal bindings

| Component | SHA-256 |
| --- | --- |
| Pinned kernel BTF | `d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb` |
| Image manifest v5 | `817c80fbf1fbbbd8337b6811693061446384e70d185a173b1db55cb0e2a83842` |
| Combined initramfs | `11dd94ed5bb9a8b96e545c0f41e7bb464f2fd34af6204c114675402decd4daee` |
| Actual signed host helper / packet sensor | `3e557fa6bbbd289ff90645072760198b58b6ceb2759f1fa1381bba516346a232` |
| Guest sensor configuration | `fa2d74eee15f43f3f2a640bf58587273dfca5a0787ce4f45af8e2dc24f932713` |
| Host packet-sensor configuration | `02c45f489ab65895da1020990aba470c3cd06471b219e34543bb1466069ffe00` |
| Root-disk-absence record | `43c4efcdf0d153f4b75c7ff3306b88ad2a9cf8a2e3687275b95feaefcda9e936` |
| Guest evidence public key | `bd7f25d9b75f79d398cb73cd4b3dc1a4ce05941598e89b854151a595859c9432` |
| Host evidence public key | `15aecb608562ca7779f8dd413f0959af2e742fd23f46c53a6c62401f60fd7190` |
| Telemetry requirements | `3ff8c862243232fbc48ec91d5926e587bf9817f678853d02d9730cde2c464946` |

Rust constructed the record from exact inputs. A separate Swift executable decoded the retrieved
remote bytes, enforced canonical JSON and the complete schema, checked the independently supplied
requirements digest, recomputed the same identity digest, and again reported unqualified state,
execution authority false, package execution false, and sync-back false.

## Claim boundary and next gate

This identity is concrete enough to issue the forthcoming fork/exec/exit run spec and challenge,
but it is not qualification and does not prove either private key is available inside the correct
authority boundary. The guest seed has deliberately not yet been provisioned, and no live receipt
was signed.

The next gate is a measured root-only guest signer/key path plus a bounded host-to-guest challenge
channel. The guest must validate the exact run context, derive claims from the ordered payload, sign
inside the VM, zeroize transient secret material, and return a receipt that Rust and Swift verify
against this identity. The host lifecycle receipt remains independently signed. Package execution
stays disabled.
