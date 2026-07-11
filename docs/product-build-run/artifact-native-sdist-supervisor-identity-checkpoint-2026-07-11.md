# Artifact-Native sdist Supervisor Identity Checkpoint

Date: 2026-07-11

Status: the Rust macOS guest supervisor now has separately compiled sdist supervisor and keygen
identities that dispatch only the existing non-executing sdist guest session; base-image
provisioning, Swift measured-base verification, VZ launch, build-closure transport, and package
execution remain open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Swift Authorized Guest Checkpoint](artifact-native-sdist-swift-authorized-guest-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Authenticated Session Checkpoint](artifact-native-sdist-authenticated-session-checkpoint-2026-07-11.md)

## Outcome

The macOS VM crate now builds two additional binaries:

- `whoathere-sdist-supervisor`; and
- `whoathere-sdist-supervisor-keygen`.

They reuse the reviewed artifact/wheel supervisor implementations through compile-time binary
identity, while selecting an sdist-only contract. The supervisor recognizes exactly its compiled
binary name and selects:

- config schema `whoathere.sdist_guest_supervisor_config.v1`;
- config path `/Library/Application Support/WhoaThere/sdist-supervisor.json`;
- signing seed `/Library/Application Support/WhoaThere/sdist-supervisor-ed25519.seed`;
- private staging root `/var/db/whoathere/sdist-staging`;
- host VSOCK port `47081`; and
- `run_macos_sdist_guest_nonexecuting_session_v1` as its sole session implementation.

The key generator likewise writes only `sdist-supervisor-ed25519.seed` and
`sdist-supervisor-public-key.bin` for the sdist binary identity. Artifact and wheel paths, schemas,
ports, and reason codes remain distinct.

## Non-executing dispatch

After the existing root, argv, trusted-file, canonical-config, key, measured-executable, VSOCK, and
deadline checks, the sdist branch constructs:

- measured sdist guest authentication claims from the running supervisor and closed config;
- an sdist staging policy rooted at the private sdist directory; and
- the existing authenticated sdist session that stages, rehashes, removes, and attests the exact
  artifact without executing package code or materializing the build closure.

The supervisor accepts no command-line configuration and cannot select the npm or wheel session at
runtime. A non-macOS build now also emits an identity-specific unsupported-platform reason.

## Verification

Verification completed on inert code and generated test data:

- the complete `whoathere-macos-vm` crate test suite passed;
- all six supervisor and keygen binary targets passed their unit tests;
- each compiled supervisor target proved its distinct identity and port;
- the sdist config schema is accepted only in the sdist domain;
- key generation writes matching Ed25519 seed/public-key pairs for artifact, wheel, and sdist
  identities and refuses overwrite;
- all 18 existing sdist backend/session tests passed;
- `cargo fmt --all -- --check` passed; and
- Clippy passed for all crate targets with warnings denied.

No VM, disk image mutation, package manager, build backend, network, restricted sample, or malware
was used.

## Claim boundary and next gate

This checkpoint proves a compiled guest-binary identity and dispatch contract. It does not prove
that a base image contains the binary, config, key, launch daemon, runtime, or correct receipt. It
also does not prove that Swift measures those objects or launches VZ on port `47081`.

The next slice is to add the sdist supervisor provisioning receipt and stopped-base provisioner,
then add matching Swift receipt verification and measured-base lifecycle. Only after those exact
measurements are bound may the helper expose `sdist-run` and start a VM.
