# Artifact-Native sdist Build-Closure Staging Checkpoint

Date: 2026-07-11

Status: the production non-executing sdist route now requires, transports, stages, rehashes,
cleans, and signs evidence for the exact offline build closure; no build or package code is enabled

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Build-Closure Transport Checkpoint](artifact-native-sdist-build-closure-transport-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Cancellation Checkpoint](artifact-native-sdist-cancellation-checkpoint-2026-07-11.md)

## Outcome

`sdist-run` now requires `--build-closure-fd 3`. No arbitrary descriptor or path is accepted. The
route proves descriptor 3 exists and is distinct from standard input before reading its closure
manifest. The authority-first sequence is:

1. read and validate only the target sdist prefix, header, and complete typed run spec;
2. atomically consume the exact sdist launch authority;
3. read and validate only the separate closure prefix and repeated canonical manifest from
   descriptor 3;
4. verify the measured stopped base and create one disposable clone;
5. authenticate the measured sdist guest supervisor;
6. stream the exact target body from standard input;
7. stream the exact closure payload from descriptor 3;
8. verify the guest’s signed combined staging receipt;
9. require guest-channel EOF, stop the VM, and prove session termination; and
10. delete the clone only under the existing terminal policy.

Neither target nor closure payload bytes are consumed before authority. Neither is sent before
guest authentication.

## Combined guest framing

The standalone target-frame API remains strict and requires EOF. The production combined-session
API reads exactly the target frame’s declared body and then requires the distinct `WHOSGCL1`
closure frame. Only the closure frame may terminate the host-to-guest write side, so:

- closure bytes cannot be mistaken for target trailing data;
- target truncation cannot consume closure bytes silently;
- the closure parser receives the exact next byte after the target body; and
- EOF remains mandatory immediately after the declared closure payload.

## Guest custody

The root supervisor creates all three inert files inside the unique scenario staging directory:

- `artifact.sdist`;
- `build-closure.manifest.json`; and
- `build-closure.payload`.

Each file is created with `O_NOFOLLOW | O_CLOEXEC | O_EXCL` behavior through `create_new`, synced,
made root-owned read-only mode `0444`, reopened without following links, and checked for a single
link, exact length, device, and inode. The closure payload is independently rehashed after staging;
the manifest is compared to the run-spec closure and separately hashed.

The closure payload remains a concatenation of exact dependency artifacts at manifest-declared
boundaries. It is not unpacked into package-manager inputs, installed, imported, executed, or made
available through a build environment in this checkpoint.

Cleanup removes the closure manifest and payload before the target and scenario directory. Any
failure is surfaced through the existing supervisor cleanup-failure state.

## Signed evidence

The Ed25519 staging receipt now additionally binds:

- closure payload SHA-256;
- closure artifact count;
- closure payload byte length;
- canonical closure-manifest SHA-256;
- staged closure device and inode;
- fixed closure file names and mode; and
- `closure_transport_verified=true`.

The signature remains bound to the fresh guest-authentication challenge, execution binding, run
spec, build-closure identity, clone binding, measured guest key, target rehash, and package UID/GID.
The only accepted posture remains:

- `package_execution_enabled=false`;
- `sync_back_enabled=false`; and
- `build_closure_materialized=false`.

The helper’s machine-readable success envelope exposes the verified closure payload, manifest,
count, byte length, and staged inode evidence. Error envelopes explicitly report closure transport
and staging as unverified.

## Verification

The inert checks prove:

- fragmented target-plus-closure streaming reaches exact frame boundaries;
- root-owned target, manifest, and payload files contain the expected exact bytes;
- file modes, lengths, digests, devices, and inodes are checked;
- combined cleanup leaves the staging root empty;
- closure rebinding fails and cleanup still succeeds;
- the signed receipt verifies in both Rust and Swift and rejects enabled unsafe capabilities;
- the Swift socket-pair session enforces authentication, target, closure, receipt, and EOF order;
- the CLI accepts only fixed descriptor 3 and rejects missing or alternate descriptors;
- the release helper retains its signal sources while blocked on intake and a direct `SIGTERM`
  exits with no authority consumed, no closure staged, and all unsafe capabilities false; and
- full Rust macOS VM and Swift helper suites pass.

No VM, package manager, build backend, public resolution, network, restricted sample, or malware was
used.

## Claim boundary and next gate

This checkpoint proves production code paths and inert in-process/socket tests. It does not prove
the provisioned supervisor binary and helper interoperate across a live VSOCK boot, nor that a
PEP 517 or legacy build can safely consume the staged closure without public fallback.

The next Mac gate remains: independently confirm a target Mac, provision and measure the stopped
base with the rebuilt supervisor, then run one inert staging-only VZ qualification. Only after that
should the package-UID build environment materialize the verified closure under a new explicit
execution authority and protected telemetry contract. Real-malware execution remains separately
gated and unauthorized.
