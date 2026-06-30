# Module Boundaries

## Modules

| Module | Responsibilities | Trust boundary |
| --- | --- | --- |
| `whoathere-cli` | Commands, shims, diagnostics, auth, local UX, exit codes. | User shell to local engine. |
| `local-engine` | Classify package-manager command, evaluate local policy, emit audit, invoke sandbox. | Trusted decision process. |
| `sandbox-runner` | Linux/macOS sandbox backends, process tree control, cleanup. | Host to untrusted install/build code. |
| `registry-adapters` | npm/PyPI parsing/rendering, lockfile/source normalization. | Untrusted package metadata to trusted model. |
| `vault-data-plane` | Registry proxy, cache lookup, artifact streaming, admission enforcement. | Client to package serving namespace. |
| `scan-detonation-workers` | Static scan, dynamic detonation, evidence collection, verdict proposal. | Quarantine execution boundary. |
| `policy-service` | Policy storage, distribution, evaluation, overrides, identity binding. | Admin intent to enforcement. |
| `audit-event-pipeline` | Append-only events, evidence references, export/search. | Evidence integrity boundary. |

## Interface Ownership

| Interface | Owner | Collaborators |
| --- | --- | --- |
| CLI commands and exit codes | `whoathere-cli` | `local-engine` |
| Local configuration | `whoathere-cli` | `local-engine`, `sandbox-runner` |
| Endpoint interceptor contract | `whoathere-cli` | `local-engine` |
| Endpoint isolation contract | `sandbox-runner` | `local-engine` |
| Policy schema | `policy-service` | `local-engine`, `vault-data-plane` |
| Audit schema | `audit-event-pipeline` | all modules |
| Vault admission API | `vault-data-plane` | `policy-service`, `scan-detonation-workers` |
| Provider authority contract | `vault-data-plane` | operations |
| Secret/key lifecycle | operations | `policy-service`, `vault-data-plane` |
| npm/PyPI compatibility | `registry-adapters` | `vault-data-plane`, `local-engine` |
| Scanner/detonator job schema | `scan-detonation-workers` | `vault-data-plane` |
| Cache object naming | `vault-data-plane` | `scan-detonation-workers` |
| Override/break-glass | `policy-service` | `whoathere-cli`, `audit-event-pipeline` |

## Unsafe/FFI Rule

Unsafe Rust and FFI are permitted only in platform adapter crates. Each unsafe block must include an invariant comment, tests, and reviewer signoff.

