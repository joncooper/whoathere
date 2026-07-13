# Artifact-Native Linux VZ Package-Runtime Clone Preflight Checkpoint

Date: 2026-07-13

Status: the exact package-runtime candidate has an independently verified, fail-closed macOS clone
and VM-configuration boundary; it has not booted under Virtualization.framework and is not qualified

## Outcome

The host helper now has a separate package-runtime composition path rather than weakening the
qualified diskless conformance configuration. It performs three pre-boot operations:

1. Strictly decode the canonical runtime manifest and require the pinned Alpine, Node/npm,
   Python/pip, package identity, no-network, non-execution, and no-sync policy fields.
2. Open, exclusively lock, and hash the rootfs, runtime manifest, and package runner through
   non-following descriptors, then cross-check all three external identities against the manifest.
3. Create a unique writable APFS clone in a random owner-controlled run directory, verify that it
   has a different inode and the exact base bytes, derive a canonical clone binding, and remove the
   clone on completion.

The new Linux VZ configuration contract takes only this verified clone. It retains the measured
Linux kernel/initramfs boot shape, serial console, vsock, and raw-frame host sinkhole with no
forwarding path. It adds exactly one writable virtio block device and still has zero directory
shares. There is no sync-back configuration.

## Exact candidate verification

An independent Swift executable verified the actual 1 GiB candidate from the prior checkpoint:

| Bound component | Identity |
| --- | --- |
| Raw ext2 rootfs | `sha256:1ebf6398764cdece30c622a630f19de8d19eb351c480285cd1a22b6d8f491ac7` |
| Rootfs byte length | `1073741824` |
| Canonical runtime manifest | `sha256:570c5ea738d26c79c580d4c0dd9d320d806c37e94137fadd321d204978dd6b7d` |
| Non-executing package-runtime probe | `sha256:be7a78bced66c43333b68ddf618dfda09c71b7056c9a8c5ca9e99958f56d8398` |

Two complete clone cycles produced different canonical bindings while preserving the exact initial
rootfs identity:

| Cycle | Clone binding | Initial bytes | Destroyed |
| --- | --- | --- | --- |
| 1 | `sha256:6fe6e8850e0f42ce527b1f024d12a5f44a57e41d468717cc3ce9c2e88574fa8b` | exact | yes |
| 2 | `sha256:232003a4769141ed3963ae60a05fb9ecd5a5b1def125e536809fc574db258083` | exact | yes |

The clone binding commits the base rootfs digest, initial clone digest, APFS clone implementation,
random run id, and observed clone device and inode. The clone is mode `0600`; its run directory is
mode `0700`. The verifier reopens it relative to the held run-directory descriptor and rejects a
changed inode, device, size, mode, owner, link count, or digest.

Wrong expected runner bytes and a symlinked runtime directory both failed closed with exit 65 and
no success output. The clone run directory was empty after both successful cycles.

## VM configuration boundary

The distinct configuration contract requires:

- 2 vCPUs and 1 GiB RAM by default;
- one writable `VZVirtioBlockDeviceConfiguration` backed by the verified clone;
- one `VZFileHandleNetworkDeviceAttachment` terminating at the host raw-frame sinkhole;
- one serial console and one virtio-vsock device;
- zero directory shares; and
- the same inert Linux boot command line.

The original diskless conformance configuration remains unchanged with zero storage devices. This
prevents the new composition from silently inheriting the existing 38-case qualification.

## Verification

The complete Swift helper suite passed 192 tests. New tests cover:

- exact manifest canonicalization and closed key set;
- pinned runtime and policy fields;
- rootfs, manifest, and runner cross-binding;
- unique clone ids, inodes, and binding digests;
- exact clone bytes and writable owner-only mode;
- cleanup and path absence;
- rootfs mutation, digest rebinding, and symlink rejection; and
- the one-storage-device, no-share, no-forwarding VM contract.

## Claim boundary

This checkpoint did not start a VM, attach the clone to a running VM, mount the rootfs in a guest,
invoke the runtime probe in a guest, produce guest or host qualification receipts, issue a one-use
grant, or run npm, pip, a package artifact, or malware. The two clone destructions were pre-boot
lifecycle tests, not proof of post-VM teardown.

The candidate remains unqualified. `package_execution` and `sync_back` are false in the verifier
output, and the configuration type carries no artifact bytes, scenario command, authority, or
sync-back input.

## Next gate

Build a dedicated runtime-qualification request and measured guest overlay that load only the
required virtio-block and filesystem modules, mount the exact clone, and invoke only the fixed
non-executing probe as UID/GID 65534 under the already-qualified protected sensor. Then run that
single inert composition physically on the approved cloud Mac and independently verify:

- exact kernel, initramfs, base, clone, manifest, runner, challenge, and request bindings;
- protected process/file/network/drop/health evidence with zero unexplained loss;
- one storage device, zero directory shares, and zero forwarded frames;
- stopped VM and destroyed clone; and
- no execution grant, package command, public resolver, or sync-back path.
