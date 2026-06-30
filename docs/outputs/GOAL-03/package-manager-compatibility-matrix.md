# Package Manager Compatibility Matrix

| Workflow | Support | Enforcement notes | Tests |
| --- | --- | --- | --- |
| `npm install` | MVP | Vault registry steering, lifecycle sandbox, lockfile integrity preserved. | CT-001 |
| `npm ci` | MVP | Deterministic lockfile install; CI fails closed on unapproved artifacts. | CT-002 |
| `npm run` | MVP policy coverage | Scripts run under project policy; subprocesses inherit isolation. | CT-004, CT-010 |
| `npx`, `npm exec` | MVP | Transient package execution is high risk and policy-gated. | CT-003 |
| npm scoped registry | MVP | Scope config preserved; public fallback denied for internal scopes. | CT-005, CT-009 |
| npm aliases/optional/peer/workspaces | Phase 1 compatibility tests | Native semantics preserved where registry metadata supports it. | CT-005 |
| npm git/tarball/direct URL | Policy-gated | CI fail closed unless explicitly allowed. | CT-005, CT-010 |
| `pip install` | MVP | Index steering, wheel preference, sdist sandbox. | CT-006, CT-008 |
| `pip3` | MVP | Same as pip. | CT-006 |
| `python -m pip` | MVP protected-mode handling | Shell/CI integration route; missed invocation becomes policy violation in protected mode. | CT-007 |
| `pip download` | Phase 1 policy coverage | Acquisition without install still must route through Vault/policy. | CT-008 |
| pip hashes/markers/extras | MVP | Preserve hash and marker semantics. | CT-006 |
| pip editable/direct/VCS | Policy-gated | Developer warn/block by policy; CI fail closed unless explicitly allowed. | CT-008 |

## Precedence Rules

- Command-line flags override env/config; protected mode denies flags that route around Vault unless allowlisted.
- npm lockfile `integrity` is preserved; `resolved` host rewriting is allowed only to Vault-approved URLs.
- pip hash fragments and `--require-hashes` semantics are preserved.

