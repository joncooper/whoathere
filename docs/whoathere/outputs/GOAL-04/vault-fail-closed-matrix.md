# Vault Fail-Closed Matrix

| Failure | Client result | HTTP contract | Retry | Alert | Audit | Break-glass |
| --- | --- | --- | --- | --- | --- | --- |
| Vault unavailable | Install fails in CI | 503 from edge/client | yes | critical | client-side | scoped only |
| CAS unavailable | Do not serve artifact | 503 `cas_unavailable` | yes | critical | yes | no for unapproved |
| Metadata DB unavailable | Do not decide | 503 `metadata_unavailable` | yes | critical | yes | no |
| Cache unavailable | Bypass disposable cache only if DB/CAS approved | 200 or 503 | yes | warning/critical | yes | n/a |
| Provider auth failure | Stop fetch/promote | 503 `provider_auth_failure` | yes | critical | yes | no |
| Policy engine failure | No allow decision | 503 `policy_unavailable` | yes | critical | yes | scoped only |
| Scanner failure | No promotion | 503 or manual review | yes | critical | yes | no |
| Detonator failure | No promotion | 503 or manual review | yes | critical | yes | no |
| Stale config | Use last valid only if within TTL; otherwise fail | 503 `stale_config` | yes | warning | yes | scoped only |
| Partial deploy | Serve previous approved state only | 503 if unsafe | yes | critical | yes | no |
| Rollback | Restore previous approved state | 200 or 503 | yes | critical | yes | no unapproved |

Explicit prohibitions: no public fallback, no stale secrets, no unsigned payloads, no unaudited bypass, no broad break-glass.

