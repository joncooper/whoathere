# Artifact-Native Linux VZ VM-Stop Checkpoint

Date: 2026-07-12

Status: `vm_stop` plus the twenty-nine earlier physical cases pass on one exact measured backend
identity; the backend remains `candidate_unqualified` with 8 of 38 cases pending

## Outcome

The eighth teardown-stress gate proves forced host teardown while a measured guest fixture is live.
The host transmits the full 5,095-byte challenge-bound request. The guest signer validates the run
spec, challenge, measured signer, protected sensor, and fixture bundle before launching the sensor.
The unprivileged UID/GID 65534 child can write its readiness record only after it has proved that it
cannot read or write the root-only protected sensor. The protected sensor independently requires
the exact child report, no supplementary groups, matching procfs parent and credential identity,
fixture-cgroup membership, and ordered cgroup-filtered BPF fork/exec observations.

Only after those checks does the sensor emit the exact
`WHOATHERE_SENSOR vm_stop_fixture=active` serial marker. The host waits for that marker and then
requires a successful `VZVirtualMachine.stop` callback and the `.stopped` state. The guest produces
zero response bytes, no behavior payload, and no guest receipt because the forced stop interrupts
the still-running sensor and signer. Signed host evidence binds the full request size, full
transmission, exact active-fixture marker observation, zero response, terminated channel, healthy
zero-frame packet sensor, stopped VM, and destruction of the diskless instance. Swift and Rust
reject missing, partial, rebound, coexisting channel-interruption, response-bearing, or non-active
VM-stop fields and contradictory serial evidence.

| Binding or observation | Final VM-stop case |
| --- | --- |
| Backend identity | `sha256:d0b282d74459e74b132011f93beaff73fe2085f373444c799ba524cf091733f9` |
| Entitled signed host helper | `sha256:e4a85035031191559bf72073c3dbe4030f40f0a5d7d53fa0ec29ffd183541085` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:96e24bd79ef8d6dd52b1e638e94dcbc2b04a359fd1eeb9e3e3c36f75206a8e4c` |
| Guest signer | `sha256:3139fd5c44cf91402d6bcf18bdaf1003c7ed532fecdd8844c67637887f387853` |
| Protected sensor | `sha256:adf03f55fced0a877db741446727bab2c784a3356d02d08b8f6b085b6700e01f` |
| Fixture child | `sha256:b8e66851bc627ee6af08291740c48d446a9ae9489de35c3533d8fd1d64d8089a` |
| Signed-image manifest | `sha256:dc9c8a6b03a737f4c195743084b1c11861e5ab68a396200e0f2a1db0c3d68c58` |
| Challenge | `sha256:107fe6a4451e33e627da9971920977d0bf9469ba0ec295fa3455b0f06f434a77` |
| Run spec | `sha256:ea274e602d9c0267940e9a05eadd697bfefe74bddb293c9451ec54de5792b1ad` |
| Request frame | 5,095 bytes; `sha256:e5514806e188f2eb98bf411ea95f4efc3cc9cc6c3e77ab30ec74d75c81d723b0` |
| Host lifecycle evidence | `sha256:62a42ffd9dbc83cf9d0913215e3e6b0ab29d87881a312aa2e349c225f3d601dc` |
| Host receipt | `sha256:7f86150f590b3d8b4258c66acf05dc0a51ca8192cc82b9912e58ec1fa6ec5538` |
| Sanitized serial | `sha256:596283606a9f5052ed84274ac799615546abfb167d69f8f9435ab1fda34ad5e1` |
| Stop action | `host_stop_after_guest_fixture_active` |
| Transmitted request / guest response | `5,095` / `0` bytes |
| Guest receipt / guest behavior evidence | absent / absent |
| Host terminal | `infrastructure_error_with_teardown` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two independent local image builds were byte-identical. All 30 implemented cases then ran
physically on this exact identity. All 90 downloaded request inputs matched locally and every
signed complete case passed the independent Rust verifier using pinned guest and remote-host public
keys. The restricted, gitignored sanitized 30-case archive contains 238 files and has SHA-256
`c5aec426c4d1e42cf3209918da992bb9a520ccd5c9fbd8afcbf09e756cd52a47`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. The backend cannot issue package-execution authority. The next closed gate
is `guest_sensor_death`.
