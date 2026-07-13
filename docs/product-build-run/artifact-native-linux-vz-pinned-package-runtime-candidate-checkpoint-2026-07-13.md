# Artifact-Native Linux VZ Pinned Package-Runtime Candidate Checkpoint

Date: 2026-07-13

Status: a byte-reproducible exact Linux/arm64 Node/npm and Python/pip rootfs candidate is built and
independently verified; it is deliberately non-executing and is not yet a qualified VM runtime

## Outcome

The repository now has a strict offline package-runtime acquisition, build, and verification lane.
Its tracked lock contains the exact Alpine 3.24.1 aarch64 minirootfs, 38 runtime APKs, and 19 image-
construction APKs by official URL and SHA-256. The selected runtime identities are:

- Node.js `v24.17.0`;
- npm `11.12.1`;
- Python `3.14.5`; and
- pip `26.1.2`.

Acquisition is separate from construction. The builder refuses a missing, changed, extra, or
symlinked input; refuses a changed Docker platform image or Zig version; and never pulls an image.
Construction runs in the exact pinned arm64 Alpine container with `--network none`. Package
installation uses only the already hash-checked local APK closure and disables package scripts.

The output is a canonical GNU rootfs archive, a raw 1 GiB ext2 block image with a fixed filesystem
identity, a stripped static aarch64 runtime probe, the input lock, and a canonical runtime manifest.
The package workspace and private temp directory are mode `0700` and owned by UID/GID 65534. The
runtime repository and resolver files are empty.

## Deliberately non-executing runner

The current repository-owned probe accepts only `--runtime-probe`. It returns one fixed canonical
record with:

- `execution_authority:false`;
- `package_execution:false`;
- `status:candidate_runtime_nonexecuting`; and
- `sync_back:false`.

Every other invocation exits 64. It has no command, path, environment, socket, package, or grant
input and makes no fork or exec call. It exists to prove that the exact rootfs can carry and invoke
a measured static guest component without creating an early detonation path.

An execution-capable runner will necessarily have a different digest and rootfs identity. It must
be reviewed, rebuilt, and pass the later runtime-composition qualification before any one-use grant
can be issued.

## Exact reproducible result

Two clean offline builds produced byte-identical copies of all five public outputs:

| Component | SHA-256 or identity |
| --- | --- |
| Raw ext2 rootfs | `sha256:1ebf6398764cdece30c622a630f19de8d19eb351c480285cd1a22b6d8f491ac7` |
| Canonical rootfs archive | `sha256:84860296179ff310fd7d2fa0af13e50454031463f5759873d9668aafd9d05aaa` |
| Non-executing package-runtime probe | `sha256:be7a78bced66c43333b68ddf618dfda09c71b7056c9a8c5ca9e99958f56d8398` |
| Canonical runtime manifest | `sha256:570c5ea738d26c79c580d4c0dd9d320d806c37e94137fadd321d204978dd6b7d` |
| Runtime input lock | `sha256:62f520de93071a90ce8bba75096ef147767357230e7b72271b2a5c46ee0262b0` |
| Rootfs byte length | `1073741824` |
| Filesystem UUID | `57484f41-5448-4552-5254-554e54494d45` |

The exact runtime executable identities are:

| Component | SHA-256 |
| --- | --- |
| Node executable | `sha256:cc4c34a01f8ce88bd220f59876de049754c6c73789157e380a095504224aa9e1` |
| npm CLI | `sha256:8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7` |
| Python executable | `sha256:95f57c0555bdc6237e2a70f1c88e0bcef04732131f2023728ea9c5baa63964c4` |
| pip entry point | `sha256:6d1f19b17ef3ab9b6d3532be2198766bb1709c83da6a6684152b8af1930da6fa` |

## Independent verification

The verifier separately enforces the lock and tool identities, canonical manifest key set and
fixed policies, every output digest and byte length, static aarch64 probe format, ext2 integrity,
and exact version probes. It extracts both the canonical archive and ext2 filesystem, checks the
sticky directory mode directly from the ext2 inode, normalizes only a documented `debugfs rdump`
presentation quirk, and requires byte-identical canonical archives. It separately requires the
UID/GID 65534 ownership and mode of both writable package directories, runs every identity and
version probe under that unprivileged identity with a fixed environment, and proves that the
runtime probe rejects an unauthorized invocation.

Both reproducible builds returned:

```json
{"candidate_runtime_qualified":false,"execution_authority":false,"package_execution":false,"status":"verified_exact_candidate_runtime","sync_back":false}
```

## Claim boundary

This checkpoint did not boot a VM, attach a storage device to Virtualization.framework, run npm or
pip installation against a test package, issue an execution grant, contact a public resolver, or
run any unknown, restricted, or malicious package. Docker was used only as an offline trusted image
construction and verification environment, never as a detonation environment.

The existing 38-case qualification proves the exact diskless telemetry backend. This new rootfs is
a separately measured candidate composition. Adding a block device and init integration changes the
measured VM configuration, so the old qualification is not silently inherited. The malicious-
package detection result remains 7 of 11, or 63.6%.

## Next gate

Add a dedicated Linux VZ runtime-composition configuration that attaches a unique writable clone of
this exact base image while retaining the measured kernel, protected sensors, no-forwarding network
attachment, challenge, evidence keys, and destroy-on-completion policy. The first physical run must
mount the rootfs and invoke only the fixed non-executing probe as UID/GID 65534 while proving:

- exact base and clone identities;
- no package command, package bytes, or public resolver use;
- protected process, file, network, drop, health, and teardown coverage remains complete;
- the clone is destroyed; and
- no sync-back path exists.

Only after that inert composition is independently qualified should the project implement a
closed typed one-use grant and exercise inert npm tarball, wheel, and sdist scenarios.
