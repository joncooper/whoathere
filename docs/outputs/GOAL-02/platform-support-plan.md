# Platform Support Plan

| Platform | MVP support | Notes |
| --- | --- | --- |
| macOS Apple Silicon | supported planning target | PATH shims, local engine, VM-backed isolation plan, code signing/notarization. |
| macOS Intel | supported planning target | Same behavior as Apple Silicon where feasible; VM performance validated separately. |
| Linux x86_64 | primary strong-isolation target | Namespaces, seccomp, cgroups, Landlock where available. |
| Linux arm64 | supported planning target | Same sandbox design; validate CI/container images. |
| Docker Linux | supported CI/container mode | Rootless where possible; Docker runtime constraints documented. |
| Windows | later expansion | Architecture keeps module boundaries portable but no MVP endpoint implementation. |

## Minimum Versions To Validate

- macOS 13+ for endpoint planning and notarization flow.
- Linux kernel 5.15+ preferred for Landlock/cgroup v2 coverage; fallback behavior documented for older kernels.
- Node/npm current LTS and latest stable.
- Python 3.9+ with pip current stable.

## Compatibility Commitments

- Preserve package-manager argv/stdin/stdout/stderr/signal/exit semantics.
- Do not require developers to fork npm or pip.
- Do not require TLS interception.
- Unsupported high-risk source types fail closed in CI.

