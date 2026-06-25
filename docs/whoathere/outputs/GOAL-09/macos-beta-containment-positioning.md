# macOS Beta Containment Positioning

## Decision

Phase 1 macOS is beta containment. It may include a VM-backed containment path, but the product must not claim GA-quality macOS containment until Phase 2 validates compatibility, performance, cleanup, subprocess inheritance, and package-manager behavior across Intel and Apple Silicon.

## Phase 1 Allowed Claims

- WhoaThere intercepts supported npm and pip workflows on macOS.
- WhoaThere can route package resolution through policy and Vault/private registry settings.
- WhoaThere can emit redacted audit events with correlation IDs.
- WhoaThere includes a beta VM-backed containment path when available.
- Unsupported or unavailable containment is visible in CLI output and JSON events.

## Phase 1 Prohibited Claims

- "Strong macOS sandboxing" without VM backend active.
- "Equivalent to Linux containment."
- "All lifecycle/build subprocesses contained" without CT-004/CT-010/CT-011 evidence.
- "GA protected mode" for macOS.

## CLI Mode Labels

| Condition | User-visible mode | CI/high-risk behavior |
| --- | --- | --- |
| VM backend active and tests pass for current workflow | `macOS beta containment` | Allow only if policy permits beta; otherwise fail closed. |
| VM backend unavailable | `macOS telemetry/interception only` | Fail closed for high-risk and CI. |
| Endpoint Security telemetry only | `macOS observe` | No containment claim; fail closed for high-risk if containment required. |
| Backend error or cleanup uncertainty | `macOS containment unavailable` | Fail closed. |

## Phase 2 Graduation Criteria

- VM backend installs into host projects without corrupting permissions, symlinks, caches, or virtualenv/node_modules layouts.
- Subprocesses inherit policy and correlation ID.
- Network decision table passes CT-010.
- Cleanup leases and janitor pass CT-011 across timeout, signal, crash, sleep/resume, and reboot.
- Native npm modules and PyPI sdists/wheels pass compatibility fixtures.
- User-facing docs and CLI output distinguish beta limitations from GA protection.

