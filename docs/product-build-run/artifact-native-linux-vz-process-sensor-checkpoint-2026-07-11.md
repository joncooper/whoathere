# Artifact-Native Linux VZ Process-Sensor Bootstrap Checkpoint

Date: 2026-07-11

Status: one root-owned, cgroup-filtered eBPF bootstrap sensor observed an inert unprivileged
fork/exec/exit chain on a physical Apple Silicon Mac; this is not a signed conformance receipt and
does not qualify the backend or authorize package execution

Follow-on: the
[ordered process-evidence checkpoint](artifact-native-linux-vz-ordered-process-evidence-checkpoint-2026-07-11.md)
adds a strict host-validated payload and receipt-claims bridge; live guest signing remains pending.

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Telemetry Feasibility Decision](artifact-native-telemetry-feasibility-decision-2026-07-11.md)
- [Linux VZ Inert-Boot Checkpoint](artifact-native-linux-vz-inert-boot-checkpoint-2026-07-11.md)
- [Linux VZ Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The measured inert image now contains two new static aarch64 binaries:

- a root-only sensor bootstrap that creates and enters a dedicated cgroup, calibrates its kernel
  cgroup identity through eBPF, and attaches raw-tracepoint programs for process fork, exec, and
  exit; and
- a separate trusted inert fixture that receives no sensor descriptors, clears supplementary
  groups, drops to UID/GID 65534, verifies it cannot read or write the sensor binary, and exits.

The sensor accepts success only when its protected BPF map contains all three observations and the
recorded process identities match the expected root parent and unprivileged child. It then emits
eight exact process-sensor markers. The v2 host evidence parser requires those markers in addition
to the twelve existing platform markers and rejects substrings or omissions.

The successful physical-host run produced:

- `status=ok` and `exit_code=0`;
- `process_sensor_marker_present=true`;
- eight of eight exact process-sensor markers;
- twelve of twelve exact platform markers;
- `missing_required_markers=[]`;
- `image_identity_stable=true` and `vm_stopped=true`;
- `raw_frame_count=0`;
- `external_route=false`;
- `package_execution=false`; and
- `sync_back=false`.

## Protection boundary

The canonical overlay fixes the relevant ownership and modes:

| Path | Mode | Purpose |
| --- | --- | --- |
| `/whoathere` | `0711` | Allows traversal without directory listing. |
| `/whoathere/capability-probe` | `0700` | Root-only platform probe. |
| `/whoathere/process-sensor-probe` | `0700` | Root-only sensor bootstrap. |
| `/whoathere/process-fixture-child` | `0555` | Trusted inert unprivileged fixture. |

The base initramfs creates `/` as `0700`, so the trusted init changes only that directory to `0755`
before the privilege-drop test. The sensor and capability binaries remain root-only. The sensor
closes every BPF map, program, and raw-tracepoint descriptor in the child before clearing groups and
dropping GID/UID. The child explicitly proves both read and write denial against the sensor path.

## Reproducible identity

Two clean builds produced byte-identical manifest and combined-initramfs bytes, and both the local
and remote verifier accepted the exact archive entry set, content hashes, protection modes, static
aarch64 format, source pins, and combined gzip stream.

| Object | SHA-256 |
| --- | --- |
| Image manifest v4 | `ed8a0ba4e5a03c67967d4b8877ec96229c6ff4876583de85fa3873c07b75c84c` |
| Raw kernel `Image` | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Canonical overlay CPIO | `fc09b6c8b0956dd36525aa7e68af780b3e929f7bd620180997dfa258f3128051` |
| Deterministic compressed overlay | `8d934449a8bdf0e2de6d62c9417945d9a2fda6ff2c8c0f6303ee7363b5068541` |
| Combined initramfs | `8cd0c65d43106224bcb9d4b9db60bfa381380019772f0ed2e5f0efac21ab0958` |
| Process-sensor bootstrap | `a72a105d63f873a5cf20d1662c96a526e59e1c62dc875885f3d79fe47d6c9894` |
| Unprivileged process fixture | `da6d23d81db798cef0e301a1ea8999250c54a2d0efc41434814eb49d7048b144` |

## Verification

The final slice passed:

- two independent byte-identical image builds;
- the strengthened local and remote image verifier, including exact protection modes;
- cross-compilation of both new C programs as stripped static aarch64 executables with warnings
  denied;
- all 99 Swift helper tests;
- all 90 Rust macOS VM tests;
- workspace Clippy with warnings denied and Rust formatting;
- the canonical 38-case contract verifier; and
- one successful physical-host boot whose canonical v2 result exited zero.

## Fail-closed development evidence

Two intermediate boots were retained only as restricted local lab diagnostics:

1. the initial sensor revision failed with every sensor marker absent; and
2. bounded stage diagnostics identified that the child could not traverse the Alpine initramfs's
   root directory after dropping privileges.

The fix made the root traversable while making the sensor itself root-only and adding explicit
read-denial proof. No marker requirement was removed, no failure was relabeled as success, and each
failed run stopped the VM with a nonzero host result.

## Evidence custody

The sanitized successful-run snapshot is gitignored under:

```text
.whoathere/remote-evidence-snapshots/linux-vz-process-sensor-2026-07-11-sanitized/
```

| Sanitized evidence | SHA-256 |
| --- | --- |
| Canonical boot result | `a94e77f5e2939412d967bc82546a273649a4f89482296430da4d8bf723506a05` |
| Host preflight | `9efdf5213adb974d1e5f6ee183c639ad3fb6d9493639c97faad6cb8c30dcda5b` |
| Inert serial log | `4118901ee34730ab95babefe3668be107b5ecfbdae0f6539d3fff8fd034747bf` |

No package artifact, package manager, malware, credential, canary, public route, live C2, second
stage, sync-back path, provider identifier, or remote address is present in tracked files.

## Claim boundary and next gate

This bootstrap proves that root-owned eBPF programs can calibrate cgroup identity and observe the
first inert process-lineage sequence while a separate fixture runs without sensor access. It does
not yet implement the final ring-buffer event stream, sequence binding, reservation/drop counters,
heartbeats, signing key, authenticated guest receipt, credential-change or dynamic-library
observation, teardown stress, file/fanotify coverage, or network evidence.

Consequently, it is not yet a verified `fork_exec_exit` conformance case and cannot contribute a
receipt to the 38-case qualification aggregate. The next slice is the measured guest event channel:
ordered process events, explicit drop accounting and heartbeat state, and a challenge-bound signed
guest receipt for the single inert process case. Only after that receipt verifies should the
remaining process, file, network, fault, teardown, and isolation cases be implemented.
