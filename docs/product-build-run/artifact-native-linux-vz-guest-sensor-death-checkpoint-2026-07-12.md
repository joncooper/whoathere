# Artifact-Native Linux VZ Guest-Sensor-Death Checkpoint

Date: 2026-07-12

Status: `guest_sensor_death` plus the thirty earlier physical cases pass on one exact measured
backend identity; the backend remains `candidate_unqualified` with 7 of 38 cases pending

## Outcome

The first sensor-tamper gate proves fail-closed behavior when the protected guest sensor is
terminated. The full 5,140-byte request is validated before the measured signer launches the exact
sensor and fixture. The unprivileged UID/GID 65534 child reports readiness only after proving it
cannot read or write the protected sensor. The sensor independently binds that report to package
credentials, no supplementary groups, procfs parent identity, fixture-cgroup membership, and
ordered cgroup-filtered BPF fork/exec observations.

The measured signer reads that exact readiness record, sends SIGKILL to the sensor process, verifies
signal 9, and returns an exact injected-failure marker without producing a response or guest
receipt. The diskless VM then powers off through the fail-closed init path. Signed host evidence
binds the full request and transmission, readiness marker, signal 9, zero response, terminated
channel, healthy zero-frame packet sensor, stopped VM, and destroyed instance.

| Binding or observation | Final guest-sensor-death case |
| --- | --- |
| Backend identity | `sha256:01a0f1c7c534d62b604cd19e512200ee3358539364badafb77c324acc8d9a50e` |
| Entitled signed host helper | `sha256:04a22e4e94b18cce64d9fad0b8eeca1a7519eb27c6b76cf8b3f96cfb2355fc33` |
| Signed initramfs | `sha256:209b0d3f192d9bb5f2415c14942779a37d61cdd5d02067ec2849e4b795c8694c` |
| Guest signer | `sha256:161149e91d96600626fdef30691dbf46b9c84c433c9fe33ebd094abbbee6d084` |
| Protected sensor | `sha256:1125f4be97ac0489e273b2d3346aac73068c9dde22929668eecd93fd5ad87e3c` |
| Fixture child | `sha256:1f93329f6d3c45d234c35d3440bb9c2b0d3075c672008b58c95a62ed42f5c1d3` |
| Signed-image manifest | `sha256:d113f982297f3f47692346db9e3398d44abf3a8f4b3813cc6329157d3a0e89cb` |
| Challenge | `sha256:377f7e151658b6f504828cb2f3e9418a34e52d4dcf49d4735fcd77318c908f89` |
| Run spec | `sha256:77ef3afa2be13f5ca68e99dc0757fac9982a290bc11b7afcc0323107634252e1` |
| Request frame | 5,140 bytes; `sha256:16be69231b707411d3993ff2ea8d23c985372cba9abf5f3882d9693481adc4ae` |
| Host lifecycle evidence | `sha256:0ddae27cbad6a3befc9c880a0743f442abfe8ec5eb587df1f1bfcdb04765ad3d` |
| Host receipt | `sha256:926dc7b05cfcb0a6d6227996384810aa24771a3c83eee357eeca0ad3a904b77e` |
| Sanitized serial | `sha256:d984e04ddf439db84121e4cc8610af41b4e2508e7a9d680643ac3a6db722f42b` |
| Guest sensor signal / response | `9` / `0` bytes |
| Guest receipt / behavior evidence | absent / absent |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

Two independent local image builds were byte-identical. All 31 implemented cases ran physically on
this identity. All 93 downloaded request inputs matched locally and every complete case passed the
independent Rust verifier. The restricted, gitignored sanitized archive contains 245 files and has
SHA-256 `6e42da16d61f87a0d253ea44644cc3fc70dc573dd3ced98f7ead62f44354bd09`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, restricted, or malware
package code ran. The backend cannot issue package-execution authority. The next closed gate is
`host_sensor_death`.
