# Artifact-Native Wheel Supervisor Provisioning Checkpoint

Date: 2026-07-10

Status: stopped-image wheel supervisor provisioning workflow and non-mutating self-test implemented;
no VM image was modified and no actual VM was launched by this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Wheel Helper Lifecycle Checkpoint](artifact-native-wheel-helper-lifecycle-checkpoint-2026-07-10.md)

## Outcome

`provision-wheel-supervisor.sh` now provides the wheel-only counterpart to the existing npm
artifact-supervisor provisioner. It fails closed unless the state and bundle directories, stopped
disk image, release supervisor binary, and release key generator are present as non-symlinked
objects. Preflight refuses a live runtime before requesting root authority or attaching the disk.

When explicitly executed by an operator against a stopped image, the workflow is designed to:

1. create a fresh wheel-only Ed25519 seed and public key;
2. ad-hoc sign and verify the measured `whoathere-wheel-supervisor` release binary;
3. write the closed `whoathere.wheel_guest_supervisor_config.v1` config;
4. attach the stopped disk with owners enabled and locate its Data volume;
5. require one unambiguous real Python executable and one installed pip `__main__.py` plus pip
   `METADATA` under the measured offline runtime;
6. obtain Python's version using `-I -S`, parse pip's version as inert metadata, and enforce optional
   operator-supplied expected versions;
7. install the root-owned supervisor, seed, config, launch daemon, and private wheel staging root;
8. preserve the dedicated unprivileged `_whoatherepkg` account contract;
9. detach the disk before publishing host-side measurements; and
10. atomically publish the public key and canonical wheel provisioning receipt into the bundle.

The workflow does not download dependencies, contact a registry, install a submitted wheel, launch
pip, import package code, or enable a network device. It measures an already provisioned trusted
Python/pip base only.

## Canonical receipt

Receipt rendering is factored into `wheel-supervisor-receipt-lib.sh`. The renderer emits one
byte-stable, lexicographically keyed `whoathere.wheel_supervisor_provisioning.v1` object containing:

- base generation, clone implementation, CPU, and memory identity;
- guest supervisor, Ed25519 public key, fixed runner config, and wheel guest-protocol digests;
- measured Python executable and pip CLI digests plus observed versions;
- package UID, GID, and username;
- wheel VSOCK port `47080`; and
- structural `false` values for package execution and sync-back.

That exact shape is accepted by the Swift stopped-base verifier added in the preceding lifecycle
checkpoint. The npm artifact supervisor remains on its distinct receipt schema and port `47079`.

## Verification

The following non-mutating gates passed on 2026-07-10:

| Gate | Result |
| --- | --- |
| Wheel provisioner shell syntax | passed |
| Wheel receipt renderer shell syntax | passed |
| Wheel provisioning self-test | passed |
| All macOS VM Rust release binary targets | built |

The self-test uses temporary directories, inert placeholder executables, and an empty placeholder
disk. It proves the safe preflight result, owner/mode rejection, port and no-execution/no-sync
output, live-runtime rejection, and byte-exact canonical receipt rendering. It does not exercise
`hdiutil`, root writes, launchd, a real disk, VSOCK, Python, pip, or a VM.

No restricted artifact, package code, registry access, network connection, cloud Mac, or malware
was used.

## Open gates

The next landing must:

1. run the provisioner against an approved stopped inert test base and independently verify every
   installed path and published digest;
2. make orchestration derive `WheelRunBackendIdentity` directly from that measured receipt and the
   base disk/helper measurements;
3. issue the short-lived single-use wheel authority record and invoke `wheel-run` without
   operator-authored hashes;
4. boot one disposable clone with the inert supervisor, complete the staged-no-execution VSOCK
   session, stop it, and verify channel and clone absence; and
5. keep Python/pip package execution and all restricted-malware gates closed until those lifecycle
   facts are proven.
