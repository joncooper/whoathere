# CodeArtifact Baseline

## Purpose

AWS CodeArtifact is a buy/build baseline, not the assumed Vault architecture. It should be evaluated as a managed package repository component or migration bridge, but it does not replace WhoaThere Vault's admission, detonation, policy, and evidence requirements.

## Baseline Findings

| Requirement | CodeArtifact fit | Gap |
| --- | --- | --- |
| npm/PyPI repository compatibility | Strong managed baseline. | Does not by itself implement WhoaThere verdict/evidence policy. |
| External upstream connection | Supported managed feature. | Upstream package may become reachable before custom detonation unless wrapped. |
| VPC/private access | Good AWS integration options. | Still needs WhoaThere control plane and fail-closed source policy. |
| Scan-before-serve | Not sufficient alone. | Requires custom admission gate before cache promotion. |
| Detonation | Not provided as WhoaThere needs it. | Requires separate scanner/detonator pipeline. |
| Digest-bound audit/verdict | Partial package metadata exists. | Requires WhoaThere verdict schema and audit events. |
| Break-glass/manual review | Not native to WhoaThere semantics. | Requires policy service and audit workflow. |

## Decision Boundary

CodeArtifact may be used only if the implementation plan proves:

- no unscanned public artifact is served to protected clients
- WhoaThere owns the allow verdict before client reachability
- dependency confusion and source policy rules remain enforceable
- audit and evidence records bind to digest/context/policy
- rollback and revocation preserve WhoaThere fail-closed semantics

If these are not proven, CodeArtifact remains a comparison baseline only.

