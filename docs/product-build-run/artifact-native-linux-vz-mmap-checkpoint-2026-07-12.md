# Artifact-Native Linux VZ mmap Checkpoint

Date: 2026-07-12

Status: the distinct closed `mmap_access` case passed physically and independently on the same
measured backend identity as the process and protected-file cases; the backend remains
`candidate_unqualified` with 35 of 38 physical cases pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [File-Telemetry Checkpoint](artifact-native-linux-vz-file-telemetry-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The request builder compiled a fresh `mmap_access` run spec and challenge against backend identity
`sha256:30f7967c30678d49b4b98d1ceca36a31ea23ed3e7da2cbc953ee1cb6668abce5`.
The physical Apple Virtualization.framework run accepted only the measured inert runner as UID/GID
65534. The root-owned sensor produced eight bounded file events, including at least one raw
tracepoint BPF mmap observation correlated to the fixture PID and calibrated package cgroup. It also
reported five fanotify permission responses, two heartbeats, zero drops, complete protected
filesystem diff and descendant teardown, no raw paths, and no truncation.

The host independently reported zero raw or external frames, a stopped VM, a destroyed diskless
clone, and a healthy packet sensor. Swift verified both signed evidence streams and the complete
case. A separate Rust invocation then read the retained serial and receipt bytes, decoded the guest
and host payloads independently, rederived their claims, verified both signatures, and reproduced
the complete-case binding.

| Binding or observation | Value |
| --- | --- |
| Backend identity | `sha256:30f7967c30678d49b4b98d1ceca36a31ea23ed3e7da2cbc953ee1cb6668abce5` |
| Signed host helper | `sha256:3d829bbf8055d481d817a193db3752454bd3ad82889f53bbdea07b0658dae0bb` |
| Signed initramfs | `sha256:f41650da94ddca69b3e1d15c270fcfb34c89b170599fcbe477679765a300fc75` |
| Challenge | `sha256:7bd55500aec2bd3220876adb1bd45df63030e85a069d2fa83f3141ef5001e08c` |
| Run spec | `sha256:ee775afe2719f3f413c53d67c9f13d2ed1a769d33fcc65b44649e4ea84131fe9` |
| Guest file evidence | `sha256:d0062ae27bd818c1182cc69f30252ca202458efedfabfbe2c05631f3a43f7a6b` |
| Guest receipt | `sha256:0158f43b4ae9f08c085752e73f7935ca336aea2eb10183f36470510b08d5a3bd` |
| Host evidence | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:5fe52e14943d6a10eeca559a6aac245cdee3703d8ef7e90c5fde507688c48f00` |
| Sanitized serial | `sha256:320dbff2c36e40683135a2aa3226c044cafe2206c221c94dd6346421d777622e` |
| Raw/external frames | `0` / `0` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

## Boundary and next gate

This is protected telemetry qualification, not package detection. No npm, PyPI, unknown,
restricted, or malware package code ran, and no live external route was configured. The mmap event
is correlated by PID/cgroup and the closed measured fixture action; the BPF record does not carry a
file descriptor or pathname. The canonical payload timestamp preserves record ordering and is not
claimed as the mmap syscall's native kernel timestamp.

Three of the 38 physical conformance cases now pass on one exact measured identity. The backend is
still unqualified and cannot issue package-execution authority. The next implementation gate is the
remaining process-lifecycle fixture coverage before network, fault, teardown, platform, and
isolation cases.
