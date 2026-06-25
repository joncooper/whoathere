# First-Miss UX

## Options

| Option | Decision | Rationale |
| --- | --- | --- |
| Blocking install until verdict | default for CI | Deterministic and secure; may be slower. |
| Deterministic failure with prewarm command | default for developer when wait budget exceeded | Keeps package-manager behavior predictable. |
| Lockfile/requirements pre-admission | recommended for CI | Moves cold misses before critical build path. |
| Silent background admission | rejected | Can hide security state and confuse package managers. |

## Client Responses

- Approved: native package-manager response.
- Pending: clear pending/manual-review message with admission ID.
- Denied: policy reason and audit ID.
- Retryable outage: retry hint, no public fallback.

## Prewarm

`whoathere cache prewarm <lockfile-or-requirements>` submits package coordinates and artifacts for admission before install.

