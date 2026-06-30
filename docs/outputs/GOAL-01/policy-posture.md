# Policy Posture

## Verdicts

- `allow`: continue normally and record audit event.
- `warn`: continue only where policy permits warning mode; record audit event.
- `deny`: block and return deterministic error.
- `quarantine`: block serving/execution while evidence is retained for analysis.
- `manual_review`: block until approved or denied.
- `break_glass`: allow only with scoped, time-bound, audited authorization.

## Defaults By Environment

| Environment | Default posture |
| --- | --- |
| CI | Fail closed for unapproved cache miss, unsupported source type, policy outage, scanner outage, detonator outage, and internal namespace conflict. |
| Developer laptop | Block known malicious/high-confidence risk; warn only for policy-approved compatibility cases; fail closed for internal namespace conflicts and explicit policy denies. |
| Vault detonation | Deny network by default; allow recorded egress only for controlled experiments. |
| Security admin | Can approve manual review and break-glass by policy; cannot create silent permanent allow through break-glass. |

## Workflow Defaults

| Workflow | Default |
| --- | --- |
| `npm install`, `npm ci` | Route through Vault when configured; sandbox install/build scripts; block unapproved artifacts in CI. |
| `npx`, `npm exec` | Treat transient package execution as high risk; require allow verdict or break-glass in CI. |
| `pip install`, `pip3`, `python -m pip` | Prefer wheels; sandbox sdist builds; route through Vault; block unsupported direct sources in CI. |
| Git/tarball/direct URL | Developer warn or block by policy; CI fail closed unless source is explicitly allowed. |
| Local/editable dependencies | Allowed only for local development policy; not admitted as public package trust evidence. |

## Data Collection Boundary

Collect package names, versions, source registry/index, artifact digest, lockfile metadata, decision, policy version, redacted evidence summaries, and correlation IDs.

Do not collect source code, raw secrets, full environment dumps, full network payloads, or complete filesystem contents.

