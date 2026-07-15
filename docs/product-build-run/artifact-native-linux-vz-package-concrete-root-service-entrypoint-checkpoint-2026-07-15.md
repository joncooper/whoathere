# Concrete protected root-service entrypoint checkpoint

Date: 2026-07-15

Status: verified code boundary; post-fork signing-seed custody, an execution-runtime qualification,
and physical package execution remain open

Subsequent progress: the post-fork descriptor/capability split was physically qualified later on
July 15. The measured runtime still must construct this service's grant-bound authority from that
one-use token and run the complete protocol. See the
[root-coordinator custody checkpoint](artifact-native-linux-vz-package-root-coordinator-custody-checkpoint-2026-07-15.md).

## Result

The Linux VZ package library now exposes one production-shaped entrypoint that instantiates the
concrete protected root process/file/network collector and drives the authenticated multi-action
sensor session. Before this checkpoint, the service loop and collector adapter existed only as
unconnected internal pieces and no caller could run their real composition.

The entrypoint deliberately does not expose the internal collector trait or resource parameters.
It fixes the BPF ring capacity at 1 MiB and the per-action process/file source-event ceiling at
65,536, both inside the collectors' existing hard limits. A caller therefore cannot replace the
collector with a fixture/no-op implementation or tune production collection to an empty or
unbounded configuration.

Sensor identity is derived only from the already verified
`QualifiedMacosLinuxVzTelemetryBackendV1`. The caller cannot separately supply or rebind the
qualified backend, guest sensor, protected BPF bundle, or sensor-configuration digests. The service
rechecks that identity against the exact authority request retained by the signing authority before
opening the control session.

The entrypoint takes the `LinuxVzPackageRootEvidenceSigningAuthorityV1` by value. Once service
startup begins, the caller cannot retain or reuse that one-use authority. The service then preserves
the existing exact open/arm/leader/finish/completion/abort state machine, per-action authenticated
incomplete receipts, bounded frames, collector fault propagation, and deny-by-construction verdict,
route, and sync-back posture.

## Custody boundary

Consuming the authority closes API ownership but is not yet physical key-custody proof. The
authority constructor necessarily receives the signing seed. If a future coordinator constructs it
before forking or otherwise isolating the root-runner branch, that branch could inherit signer key
material even though the service entrypoint later consumes the Rust value.

The required runtime architecture is therefore now explicit:

1. verify and irreversibly consume the one-use execution grant;
2. derive the exact closed execution request;
3. isolate the root-runner and root-sensor service branches before reading the guest signing seed;
4. close the seed descriptor in the runner branch;
5. only then read and zeroize the seed into the service branch's consumed authority;
6. run the fixed sequencer through the service control channel; and
7. require authenticated session completion, runner termination, VM stop, stable image identity,
   and clone destruction before host composition.

A distinct measured root coordinator must enforce that order and descriptor custody. This
checkpoint does not create a shortcut around the still-opaque execution-runtime qualification type
and does not make production grants issuable.

## Verification

Completed locally:

- macOS `whoathere-macos-vm` library tests: 233 passed;
- Linux/aarch64-musl guest-target test compilation: passed;
- native and Linux/aarch64-musl `whoathere-macos-vm` Clippy with warnings denied: passed;
- Rust formatting and diff whitespace checks: passed; and
- all prior multi-action, authenticated root-receipt, collector, fault, identity, grant, and no-sync
  tests remain green.

No VM, package, or malware ran for this checkpoint. The approved cloud Mac was not modified.

## Claim boundary

This checkpoint does not claim:

- post-fork exclusive signing-seed custody;
- a measured root-coordinator binary or execution-capable runtime image;
- an evidence-backed constructor for the opaque execution-runtime qualification;
- production execution-grant issuance;
- physical npm, wheel, or sdist qualification;
- complete network or file coverage;
- an authoritative clean or malicious verdict;
- any sync-back authority; or
- improved malicious-package detection coverage.

The July 1 result remains 7 of 11 behavior detections (63.6%).

## Next gate

Implement the measured root coordinator and its fixed descriptor contract. It must burn the grant
and derive the exact request before process separation, ensure the runner branch cannot inherit or
read the guest signing seed, and construct the consumed service authority only in the isolated
service branch. Then bind the coordinator and service identities into a distinct execution-runtime
qualification request and reproducible image. Only authenticated inert npm, wheel, and nested-sdist
runs on the approved cloud Mac may produce the evidence-backed qualification that unlocks one-use
production grants. Real-malware execution remains behind the separate restricted-lab approval gate.
