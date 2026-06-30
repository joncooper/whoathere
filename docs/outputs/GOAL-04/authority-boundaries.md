# Authority Boundaries

| Authority | AWS-only | Cloudflare-only | Hybrid recommendation |
| --- | --- | --- | --- |
| Secrets | AWS Secrets Manager | Cloudflare Secrets | AWS authoritative |
| KMS/envelope keys | AWS KMS | Cloudflare/platform keying or external KMS | AWS KMS authoritative |
| CAS blobs | S3 quarantine/promoted | R2 quarantine/promoted | S3 authoritative; R2 optional cache copy |
| Cache entries | Vault DB + S3 state | Workers Cache/R2 metadata | AWS authoritative; Cloudflare disposable |
| Package metadata | DynamoDB/Aurora | D1/KV/R2 metadata | AWS authoritative |
| Verdicts | DynamoDB/Aurora | D1/KV | AWS authoritative |
| Policy | Policy service on AWS | Cloudflare/D1/KV | AWS authoritative |
| Audit logs | AWS log/audit store | Cloudflare logs/R2 | AWS authoritative |
| Evidence bundles | S3 | R2 | S3 authoritative |
| Deployment state | Terraform/OpenTofu state in AWS-backed store | Cloudflare deployment metadata | AWS authoritative for core; Cloudflare for edge config only |
| Rollback metadata | AWS deployment system | Cloudflare deployment history | AWS authoritative for core |

Any mismatch between this file and ADR-005/006/007/011 blocks completion.

