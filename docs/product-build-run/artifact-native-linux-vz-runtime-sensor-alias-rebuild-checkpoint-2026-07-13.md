# Artifact-Native Linux VZ Runtime Sensor-Alias Rebuild Checkpoint

Date: 2026-07-13

Status: the pinned candidate now satisfies the protected sensor's closed invocation contract and
is independently reproducible and clone-preflighted; it has not booted under VZ and remains
unqualified

## Outcome

The static package-runtime probe now accepts exactly two invocations:

- `--runtime-probe`, for offline construction and independent verification; and
- `fork_exec_exit`, the fixed argument used when the already-qualified protected sensor launches
  its measured target.

Both paths emit the same fixed canonical report:

```json
{"execution_authority":false,"package_execution":false,"schema_version":"whoathere.linux_vz_package_runtime_probe.v1","status":"candidate_runtime_nonexecuting","sync_back":false}
```

No argument vector, package path, shell, interpreter, lifecycle hook, npm command, pip command, or
artifact input was added. A no-argument invocation and an open-ended `package_install` argument
both fail with exit 64. The manifest records the closed mode as
`nonexecuting_runtime_probe_with_closed_sensor_alias`.

## Reproducible rebuild

Two clean builds consumed the same 58 exact hash-locked Alpine inputs and the pinned Alpine 3.24.1
arm64 container identity. The construction containers ran with `--network none`; they were image
construction environments, not detonation environments. The two builds produced byte-identical
copies of all five outputs:

| Output | Bytes | SHA-256 |
| --- | ---: | --- |
| Raw ext2 rootfs | 1,073,741,824 | `sha256:0114f1508ca2214787af2befc64641801f26904d7d6771cbb8cd9a746d7029ae` |
| Canonical rootfs archive | 138,752,000 | `sha256:b27cb250bb8dd9fb8571c6d52ea5be051fdfb291ea0161ee852340271596ec0b` |
| Static package-runtime probe | 4,576 | `sha256:96c9ab2127e11029c1b23259afcbd7dfab984ab3ae4528555f0a8b34dc48d658` |
| Canonical runtime manifest | 2,156 | `sha256:bcfa7106cd4a604af531b7c3320625a4434009a692bbde01c953ef61e2fb23a5` |
| Runtime input lock | 9,173 | `sha256:62f520de93071a90ce8bba75096ef147767357230e7b72271b2a5c46ee0262b0` |

The new rootfs, archive, runner, and manifest identities supersede the earlier candidate checkpoint.
The pinned Node/npm and Python/pip versions and the fixed rootfs UUID are unchanged.

## Independent verification

Both builds passed the independent verifier, which:

- extracted the archive and ext2 image separately and compared canonical contents;
- checked the ext2 filesystem and fixed identity;
- rehashed the rootfs, archive, runner, manifest sources, and all runtime executables;
- ran Node 24.17.0/npm 11.12.1 and Python 3.14.5/pip 26.1.2 identity probes;
- ran both accepted probe spellings as UID/GID 65534 in an empty environment;
- required their reports to match exactly;
- rejected no-argument and open-ended invocations; and
- re-proved empty resolver/repository configuration, ownership, modes, non-execution, and no
  sync-back.

The independent Swift preflight then locked and rehashed each exact candidate and completed two
distinct clone-and-destroy cycles:

| Cycle | Clone binding | Initial rootfs exact | Destroyed |
| --- | --- | --- | --- |
| 1 | `sha256:031828e126f12a85bd06ee63d4f201e578fd5a03e31ddc666cbf4a1d33cabe86` | yes | yes |
| 2 | `sha256:488708ed604db16703ed545f6582aa66136d3e55600910b15d91990466e49df9` | yes | yes |

## Claim boundary

This checkpoint did not boot a VM, attach a clone to VZ, mount the rootfs in a running guest,
produce a signed runtime-qualification receipt, issue package execution authority, run npm or pip
against an artifact, or handle malware. The candidate remains
`candidate_exact_bytes_not_yet_independently_qualified` with package execution and sync-back false.

Real malware remains restricted to the approved cloud Mac lab workflow. Docker was used only for
pinned offline image construction and verification, never detonation.

## Next gate

Build the minimal measured qualification overlay and signed receipt around the exact new candidate.
Then boot one unique clone on the approved cloud Mac with only the canonical inert qualification
request, prove protected telemetry plus VM-stop-before-clone-destruction, and independently verify
the complete evidence. No package artifact or malware belongs in that run.
