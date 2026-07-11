# Artifact-Native Inert Wheel VM Qualification Handoff

Date: 2026-07-10

Status: live qualification command and non-mutating preflight self-test implemented; actual VM gate
not run because this workspace Mac has no local VM state and the configured remote Mac requires
operator revalidation of its changed SSH host identity

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native Measured Wheel Launch Checkpoint](artifact-native-measured-wheel-launch-checkpoint-2026-07-10.md)
- [Artifact-Native Wheel Supervisor Provisioning Checkpoint](artifact-native-wheel-supervisor-provisioning-checkpoint-2026-07-10.md)

## Qualification command

`whoathere-inert-wheel-vm-qualification.sh` is the bounded command for the first actual wheel VM
gate. It has separate `--preflight` and `--execute` modes and accepts only absolute state/evidence
paths. Before execution it requires:

- all fixed measured base, wheel provisioning, and public-key files;
- release Swift helper and measured Rust generator binaries;
- current-user ownership and no group/world-writable inputs;
- no symlinks at fixed inputs; and
- a stopped runtime.

Execution creates a new mode-`0700` evidence directory, records pre-run base disk and auxiliary
storage hashes, generates one exact inert wheel frame and two-minute single-use authority, invokes
the real `wheel-run` helper, and records the helper's complete result. It succeeds only when all of
these facts are present:

- wheel-only non-executing schema and `staged_no_execution` status;
- durable authority consumption;
- zero network devices and VSOCK port `47080`;
- VM start and VM stop;
- guest authentication and signed staging receipt verification;
- guest staging cleanup and terminal channel closure;
- clone cleanup and empty wheel-runs directory;
- unchanged base disk and auxiliary-storage hashes; and
- package execution and sync-back both false.

The command never enables Python, pip, import, `.pth`, entry-point, package-user, telemetry, verdict,
admission, or copy-back behavior.

## Verification and current environment

The shell syntax and preflight self-test pass. The self-test proves a complete safe preflight and
live-runtime refusal using temporary inert placeholders; it cannot satisfy the VM evidence gate.

The preflight on this workspace Mac returned:

```text
wheel_vm_qualification_preflight=false
reason_code=wheel_vm_qualification_state_missing_or_unsafe
```

No local state directory exists at the default path. A remote Mac is configured outside the
repository, but its presented SSH host identity differs from the previously trusted identity.
Strict verification correctly stops the connection. No address, key, provider identity, or new
fingerprint is recorded here, and the mismatch must not be bypassed with disabled host-key checks.

No VM, disk attachment, root provisioner, Python process, pip process, package code, network
connection, restricted artifact, or malware was used in this handoff.

## Resume gate

An operator must either:

1. confirm the remote Mac's new host-key fingerprint through an independent trusted channel and
   replace the stale key deliberately; or
2. provide a local stopped validation base and run the wheel supervisor provisioning workflow.

After that, run the qualification preflight first and execute only if it reports ready. Preserve the
generated evidence directory and require every fact above before closing the non-executing VM gate.
The active project goal remains open while this external machine-identity/base-state prerequisite
is unresolved.
