# Root-coordinator signing-seed custody checkpoint

Date: 2026-07-15

Status: post-fork signing-seed descriptor and ptrace boundary physically qualified with an inert
probe on the approved cloud Mac; grant-bound service construction and an execution-capable package
runtime remain open

## Result

The package runtime now has a measured root-coordinator split that keeps the guest evidence signing
seed out of the root-runner branch. Three fresh, diskless Linux VZ boots passed the strict Mac host
verifier. The accepted runs used the pinned Linux `6.18.35-0-virt` kernel and reported:

- one service process and one runner process with distinct PIDs;
- exactly one runner thread and exactly four runner descriptors: standard input/output/error plus
  the private service-control socket;
- the original seed descriptor, service socket endpoint, readiness endpoint, and every unrelated
  descriptor closed in the runner before it returned to Rust;
- `CAP_SYS_PTRACE` absent from the runner's inheritable, permitted, effective, ambient, and bounding
  sets;
- zero ambient capabilities, `no_new_privs=1`, no tracer, and a non-dumpable runner;
- a non-dumpable service that did not receive a readable seed token until the runner boundary was
  independently inspected and acknowledged;
- one exact 32-byte, nonzero seed followed by EOF, whose derived Ed25519 public-key digest matched
  the host-bound expectation;
- a normally exited runner, a stopped VM, stable kernel and initramfs bytes, and a healthy drained
  host packet sensor with zero retained, dropped, or truncated frames; and
- no root disk, directory share, external route, package execution, malware execution, or
  sync-back.

This closes the narrow physical signer-custody prerequisite identified by the preceding concrete
root-service checkpoint. It does not close AN-506: no measured execution runtime yet burns a real
package grant, derives its exact request, constructs the grant-bound signing authority from this
post-fork token, runs the concrete collector, and transports the resulting authenticated receipts
to host composition.

## Enforced coordinator boundary

The Linux-only split now fails closed unless its caller is root, has exactly one task, and supplies
one root-owned, read-only, close-on-exec FIFO descriptor with no duplicate endpoint in the
coordinator process. The service becomes non-dumpable before `fork` and does not read the seed.

The runner child then, before returning to caller code:

1. uses `close_range` to preserve only descriptors `0`, `1`, `2`, its control socket, and the
   temporary readiness pipe;
2. proves that the original seed, service-control, and service-readiness descriptors return
   `EBADF`;
3. binds its lifetime to the service with `PR_SET_PDEATHSIG(SIGKILL)` and rechecks its parent PID;
4. sets `PR_SET_DUMPABLE=0`;
5. removes `CAP_SYS_PTRACE` from its effective, permitted, inheritable, and bounding sets;
6. clears the entire ambient set, enables `PR_SET_NO_NEW_PRIVS`, and rereads each self-observable
   invariant; and
7. emits one readiness byte, closes that pipe, and blocks on the private control socket.

While the runner is blocked, the service parent independently reads the runner's bounded
`/proc/<pid>/status` and descriptor directory. It requires all four root UID/GID values, one thread,
`TracerPid=0`, `NoNewPrivs=1`, no ptrace bit in any reported capability set, an empty ambient set,
and exactly the expected four descriptors. Only then does it send a release byte. The runner
acknowledges that release before the service branch receives the non-clonable, one-use seed token.

The seed reader itself requires exactly 32 bytes plus EOF within a bounded wait, rejects an all-zero
seed and trailing data, zeroizes error buffers, and returns a `Zeroizing<[u8; 32]>`. Debug output for
the token and service branch redacts the descriptor and key material.

## Independent inert qualification path

The aarch64-musl probe self-hashes before the split and rejects a host-bound digest mismatch. The
runner and service then complete a distinct bounded control exchange. Only the service reads the
seed and derives the public key; neither branch prints or returns seed bytes. Its one canonical JSON
record contains only process IDs, capability masks, boundary booleans, the measured probe digest,
and the public-key digest.

The Mac implementation independently:

- accepts exactly one bounded coordinator evidence line;
- requires canonical JSON and an exact key set;
- rebinds the measured probe and expected public-key digests;
- parses the five 64-bit capability masks independently and rejects the ptrace bit;
- requires the exact descriptor, thread, credential, ordering, EOF, exit, and no-sync values;
- rejects duplicate evidence and any guest failure marker; and
- composes that guest record only with host-observed VM stop, stable image bytes, an isolated raw
  frame sink, and the absence of storage and shares.

The init path materialized a fresh seed into an anonymous FIFO, waited for the writer to close, and
unlinked both the seed file and FIFO path before starting the measured probe. The raw seed remained
only in the protected cloud-Mac working directory and restricted initramfs artifacts. It was not
printed, copied into the repository, or included in this document.

## Physical evidence

The canonical overlay, deterministic gzip member, and final initramfs were rebuilt independently
from the same measured inputs. All three rebuilt files were byte-identical. Three strict host runs
exited `0`; the first used the original build, the second the byte-identical rebuild, and the third
persisted the sanitized final host result.

| Component | SHA-256 |
| --- | --- |
| Pinned Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Prior inert base initramfs | `sha256:0935bcdae68270c05d23019f51f60810a1a57753146c373b7708e2399731d10c` |
| Rendered coordinator init | `sha256:2f42b0683a582a5c2b92b9aea11a22c2286666b8674fefe7dd7cf53fde76367d` |
| Static aarch64-musl coordinator probe | `sha256:20f94fb071b5a793862985effa8c2f4c3bc8fdfa57d959015589d9ea4fdf1b33` |
| Ephemeral guest public key | `sha256:7d0f3e2fd73466b0920f237816020d051276816a885de9813bb3d1d30be86790` |
| Canonical overlay CPIO | `sha256:507a31b16d134a9fa39fa3b2ecafa6132d95b04db0eb8fcc649e04e00769d832` |
| Deterministic gzip overlay | `sha256:b978e4f3334aff5f209f41b6058a3ac377f86abee0434abb3bbc96e037c9e09d` |
| Final coordinator initramfs | `sha256:287c18b6de35cb2027be31fe97982cb7a28de8ced4214a7fa75e715d92001593` |
| Strict entitled Mac harness | `sha256:30306a320a42d903083abd28a9e29ee3d546a9a6ab33a9ac50003fb15e0dd721` |
| Final sanitized serial transcript | `sha256:fc43876a03aa00a0accdf8c143f05710a39b01fadbd205ad720ebe45ab7c4671` |
| Final strict host result | `sha256:a5dc3a0507e87077c270f0191d1b4262297cbc17f7bcb39e550d9df8673cfb85` |

The probe was 802,416 bytes, the canonical overlay was 1,042,944 bytes, the deterministic gzip
member was 504,104 bytes, and the final initramfs was 13,493,247 bytes. The sanitized final serial
transcript was 1,769 bytes and the host result was 1,720 bytes.

The final host result included:

```json
{"directory_share_count":"0","evidence_byte_length":"1087","evidence_payload_sha256":"sha256:ace2cde711162e575470ac13c1e1fc2d3ffeb6f36d536ecf7a2661aa639523df","evidence_valid":true,"exit_code":0,"external_route":false,"failure_marker_present":false,"guest_evidence_public_key_sha256":"sha256:7d0f3e2fd73466b0920f237816020d051276816a885de9813bb3d1d30be86790","image_identity_stable":true,"initramfs_sha256":"sha256:287c18b6de35cb2027be31fe97982cb7a28de8ced4214a7fa75e715d92001593","kernel_command_line":"console=hvc0 rdinit=/init panic=0 reboot=k loglevel=6","kernel_sha256":"sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd","malware_execution":false,"missing_required_markers":[],"network_topology":"host_raw_frame_sinkhole_no_external_route","operation":"linux_vz_package_root_coordinator_qualification","package_execution":false,"packet_sensor_healthy":true,"packet_sensor_terminal":"drained_after_stop","probe_sha256":"sha256:20f94fb071b5a793862985effa8c2f4c3bc8fdfa57d959015589d9ea4fdf1b33","raw_frame_count":0,"raw_frame_dropped_count":0,"raw_frame_retained_count":0,"raw_frame_truncated_count":0,"required_marker_count":8,"root_disk_present":false,"runner_ambient_capabilities":"0000000000000000","runner_bounding_capabilities":"000001fffff7ffff","runner_effective_capabilities":"000001fffff7ffff","runner_inheritable_capabilities":"0000000000000000","runner_open_descriptor_count":"4","runner_permitted_capabilities":"000001fffff7ffff","runner_pid":"385","runner_thread_count":"1","schema_version":"whoathere.linux_vz_package_root_coordinator_boot_result.v1","service_pid":"384","status":"ok","storage_device_count":"0","sync_back":false,"virtualization_supported":true,"vm_stopped":true}
```

## Verification

- macOS `whoathere-macos-vm` library tests: 236 passed;
- Linux/aarch64-musl target compilation and all-target Clippy with warnings denied: passed;
- static aarch64-musl release build through `cargo zigbuild`: passed;
- Mac helper tests, including the independent strict coordinator decoder: 221 passed;
- shell syntax validation for the inert init template: passed;
- canonical overlay, gzip, and final initramfs independent byte-for-byte rebuild: passed; and
- three entitled, isolated Linux VZ host qualifications: exit `0`, canonical `status: "ok"`.

## Claim boundary and next gate

This checkpoint does not claim an execution-capable package runtime, grant-bound signing-authority
construction in the measured service, authenticated package-receipt transport from that runtime,
npm/wheel/sdist execution, broad file or network coverage, an authoritative verdict, improved
malware detection, or any sync-back authority. It also does not replace the separate parent-death
fault-injection test still required for the complete runtime.

The July 1 actual-malware result therefore remains **7 of 11 behavior detections (63.6%)**.

The next gate is to build the fixed measured coordinator binary around this split. Before forking,
it must consume the exact execution grant and derive the closed request. In the service branch it
must read this one-use token, construct the grant-bound root-evidence authority, and run the concrete
multi-action service. In the runner branch it must drive the existing fixed sequencer and supervisor
through the private socket. Those exact coordinator, service, sensor, and runner bytes must then be
bound into a new non-authorizing runtime-qualification request and reproduced image. Only after that
runtime passes inert npm, wheel, and nested-sdist qualification should benign-control measurement
begin. Real-malware execution remains behind its separate restricted-lab approval gate.
