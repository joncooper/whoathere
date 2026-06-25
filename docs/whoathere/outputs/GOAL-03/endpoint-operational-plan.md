# Endpoint Operational Plan

## Minimum Platforms

- macOS 13+ on Apple Silicon and Intel.
- Linux kernel 5.15+ preferred; older kernels require degraded-mode decision.
- Docker Linux CI runners with cgroup v2 where possible.

## Privileges And Helpers

- PATH shims are user-installable.
- Linux rootless mode requires unprivileged user namespaces and cgroup delegation.
- macOS VM helper requires signed/notarized helper and user-approved installation.
- Endpoint Security telemetry requires approved entitlement and explicit installation flow if shipped.

## Cleanup Requirements

Cleanup tests must cover:

- Normal exit.
- Policy deny.
- Timeout.
- SIGINT/SIGTERM.
- Child process crash.
- Host sleep/resume.
- Vault unavailable during command.

No lingering VM, namespace, proxy, firewall, mount, socket, temp directory, temp credential, or helper process may remain.

## Unsupported Cases

| Case | Developer mode | CI/high-risk mode |
| --- | --- | --- |
| Absolute path to package manager bypassing shim | Audit/backstop warning when detected | Fail closed after detection in protected workspace |
| Unsupported git/tarball/direct URL | Warn or deny by policy | Fail closed unless allowlisted |
| Missing Linux primitives | Warn/degraded only if policy allows | Fail closed |
| macOS VM unavailable | Telemetry/interception only; no containment claim | Fail closed for high-risk commands |
| macOS VM beta active | Label as beta containment | Fail closed unless policy permits beta mode for high-risk commands |
| Protected-context shim bypass | Fail closed after detection and report bypass signal | Direct public egress must already be blocked before execution |

## Remediation Messages

- Policy denial: show package/source/rule and `whoathere policy explain`.
- Missing privilege: show `whoathere doctor` remediation.
- Sandbox failure: show retryability and cleanup status.
- Vault unavailable: show fail-closed reason and break-glass request path if allowed.
