# Linux VZ Package-Runtime Qualification Image

This helper builds a deterministic qualification overlay on top of the already-qualified Linux VZ
telemetry image. It adds only the measured runtime-qualification agent, the exact candidate runtime
manifest, a closed module manifest, and the block/ext filesystem modules needed to inspect the
candidate rootfs.

The image accepts one typed request over virtio-vsock port `40554`. It stream-hashes `/dev/vda`,
validates its ext superblock and fixed UUID, mounts it read-only with `nodev,nosuid`, and invokes the
exact inert runtime probe through the already-qualified protected process sensor. It never accepts
a package artifact, package command, generic argument vector, execution grant, or sync-back path.

Build and independently verify it with absolute paths:

```sh
helpers/linux-vz-package-runtime-qualification/scripts/build-runtime-qualification-image.sh \
  /absolute/qualified-linux-vz-image \
  /absolute/rootfs.ext2 \
  /absolute/runtime-manifest.json \
  /absolute/output

helpers/linux-vz-package-runtime-qualification/scripts/verify-runtime-qualification-image.sh \
  /absolute/qualified-linux-vz-image \
  /absolute/rootfs.ext2 \
  /absolute/runtime-manifest.json \
  /absolute/output
```

The input qualified image must already contain the protected sensor, signing seed, and vsock
modules. The build does not print or copy the seed outside the resulting initramfs composition.
Both build and verification are inert image operations; physical boot qualification is performed
only on the approved cloud Mac. Real malware is never handled by these scripts.
