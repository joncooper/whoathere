# ADR-003: Linux Isolation Backend

- Status: accepted
- Date: 2026-06-25

## Context

Linux must provide the strongest MVP endpoint isolation for untrusted install/build scripts on developer hosts, Docker containers, and CI.

## Decision

Use a rootless namespace-based sandbox with:

- User, mount, PID, IPC, UTS, cgroup, and optional network namespaces.
- Seccomp profile for syscall reduction.
- Cgroup v2 limits for CPU, memory, pids, and I/O.
- Landlock where kernel support is available for additional filesystem restrictions.
- Read-only host binds and writable project/cache/tmp binds.
- Network modes: deny, Vault-only, and recorded-egress.
- Process-tree supervision to keep subprocesses inside the namespace/cgroup.

Bubblewrap-style execution is the reference implementation model; direct Rust orchestration is allowed only if it preserves equivalent guarantees.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Docker only | Not always available on developer hosts and weaker UX for direct project installs. |
| chroot only | Insufficient filesystem/process/network isolation. |
| seccomp only | Does not isolate filesystem or network. |
| Landlock only | Kernel availability and coverage are insufficient as sole boundary. |

## Security Impact

The sandbox denies host credential reads by default, restricts writable paths, blocks or records network egress, and keeps child processes in the same cgroup/namespace boundary.

## Operational Impact

Requires unprivileged user namespaces and cgroup v2 for full mode. `whoathere doctor` reports degraded modes and CI fails closed if required primitives are missing.

## Compatibility Impact

Native build tools work only when explicitly mounted/allowed. Packages needing network during build require recorded-egress policy or manual review.

## Cost/Performance Impact

Target sandbox startup overhead is under 250 ms for warm helper path and under 1 s cold path.

## Revisit Trigger

Revisit if rootless namespaces are unavailable on a target enterprise Linux baseline or compatibility failures exceed accepted thresholds.

