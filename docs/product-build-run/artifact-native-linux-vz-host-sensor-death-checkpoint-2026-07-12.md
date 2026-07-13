# Artifact-Native Linux VZ Host-Sensor-Death Checkpoint

Date: 2026-07-12

Status: `host_sensor_death` plus the thirty-one earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 6 of 38 cases pending

## Outcome

The second sensor-tamper gate proves fail-closed behavior when the host packet sensor terminates
while the protected guest sensor remains healthy. A dedicated host packet-sensor worker starts
before VM launch and exclusively owns the raw-frame receive path for this case. After the host
transmits the complete 5,171-byte authenticated request and half-closes the guest channel, it
injects the worker termination and waits for that exact worker to finish. The normal post-run frame
drain is not used as a substitute.

The measured guest signer independently validates the run spec, challenge, image identity, sensor,
and fixture bundle. The protected guest sensor then observes the unprivileged UID/GID 65534
fixture's cgroup-filtered fork, exec, and exit sequence, proves protected-sensor read and write
denial, emits canonical healthy evidence with zero drops, and signs a guest receipt bound to the
expected infrastructure-error terminal.

Signed host evidence records that the sensor worker started, was deliberately terminated after the
full request, and remained unhealthy with terminal `injected_sensor_death`. It also binds the exact
1,675-byte framed guest response, zero raw frames, zero drops, terminated guest channel, stopped
VM, stable image identity, absent storage device, and destroyed diskless instance.

| Binding or observation | Final host-sensor-death case |
| --- | --- |
| Backend identity | `sha256:8cf99e8752368de1803ada9d6b7933bd77c8a84106b1ac1bebff1eb6d23d567c` |
| Entitled signed host helper | `sha256:bab8ae305449bfdfe71eac0328f0daab9985b8006cb9535f7fc4f8cf2f0f1994` |
| Signed initramfs | `sha256:4a51ce16d780d8f5fac264d368fea7b7c104f5a80af651586be6b8eb5e2f3723` |
| Guest signer | `sha256:58bb1894bfa17721fc66ab38b5f99165eef3d727c152d2d90753bab7b640e1c0` |
| Protected sensor | `sha256:d1d7f781e50e96904c40bc18774beee229ff7fdf49543fac86212372ba6d9d88` |
| Fixture child | `sha256:577ddc350afd8fcb1a54c7568e333968c3d1f3d84676d0387f6f1e3fd648b9fb` |
| Signed-image manifest | `sha256:f7eeefb43b4b1e9861f4d014d2dbd224525e091002f63b89ccc63624a762ec93` |
| Challenge | `sha256:41d9b00f2da6a5c537f1164e637aa5fd5dad2c6fd3afea5427ca18c9ed77365d` |
| Run spec | `sha256:2500f43d8a313e3a763d1c524b358f45fa726a3a044ff2303f4ec4aebd857370` |
| Request frame | 5,171 bytes; `sha256:6a468e2664954345ddae67a06534b68cf9e8be05ac47f227c9ed0a82835a1179` |
| Guest behavior evidence | `sha256:40668cd5c96a19caabe38073f6b9d1e8fbc805486bc408e1db08a201e0a9484d` |
| Guest receipt | `sha256:5e6632fd505faa7760ea5297fbfd8268717f9641a9a4a55edca7581f660236bc` |
| Host lifecycle evidence | `sha256:37ab80d0285b0c67372df348be223fe87d1770fbe8975f6ebcf5d718ac33ba3b` |
| Host receipt | `sha256:323500cb426acc0dc900ecec0b1280be31a988ee44040ed2629536199580a174` |
| Sanitized serial | `sha256:a4b673b7b4943e976ed0e2bfe6d89fa2b29bad4b522559039f8ff8cd389fd2a9` |
| Host sensor / guest sensor | deliberately unhealthy / healthy |
| Request / framed response | 5,171 / 1,675 bytes |
| Raw frames / dropped frames | `0` / `0` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two independent local image builds were byte-identical. All 32 implemented cases ran physically on
this identity. All 96 downloaded request inputs matched locally and every complete case passed the
independent Rust verifier. The restricted, gitignored sanitized archive contains 285 files and has
SHA-256 `01e08865b86f8df7a586ecc2026abc1a3b1559dd379933b116117ef4099535ed`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, restricted, or malware
package code ran. The backend cannot issue package-execution authority. The next closed gate is
`all_protected_assets_denied`, followed by the five remaining platform-capability cases.
