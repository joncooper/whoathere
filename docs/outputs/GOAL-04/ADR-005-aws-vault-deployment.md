# ADR-005: AWS Vault Deployment

- Status: accepted
- Date: 2026-06-25

## Context

Vault requires hardened private network ingress, controlled public egress for upstream fetch, isolated detonation workers, durable CAS, and enterprise CI routing.

## Decision

Accept AWS-native deployment as the default production architecture:

- PrivateLink endpoint service behind NLB for consumer VPC ingress.
- ECS/Fargate or EKS for serving and workers; Batch is acceptable for heavy detonation queues.
- S3 for CAS, with separate quarantine/promoted prefixes or buckets.
- DynamoDB or Aurora PostgreSQL for metadata, verdicts, alias tables, and state transitions.
- SQS plus Step Functions/EventBridge for admission workflow.
- NAT Gateway plus AWS Network Firewall for controlled upstream egress.
- KMS for envelope encryption.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Public ALB-only Vault | Does not isolate downstream resources from public internet. |
| CodeArtifact as core | Cannot prove scan-before-serve before upstream package is reachable without wrapping constraints. |
| Single flat VPC plane | Mixes serving, fetch, and detonation trust zones. |

## Authority Boundaries

AWS is authoritative for secrets, KMS keys, CAS, metadata, verdicts, policy store, audit logs, evidence bundles, and deployment state in AWS-only mode.

## Security Impact

Strongest private-network story. Fetch workers have the only public egress. Detonation plane has no route to internal services or metadata credentials.

## Operational Impact

Requires VPC, PrivateLink, firewall, KMS, DB, queue, object-store, and multi-AZ operations. Mature runbook and observability support.

## Compatibility Impact

Works well for AWS-hosted CI and enterprise VPCs. Non-AWS users need VPN, public controlled endpoint, Cloudflare Access, or hybrid edge layer.

## Cost/Performance Impact

NAT/firewall and PrivateLink add cost. Warm-cache latency is regional unless Cloudflare or multi-region replication is added.

## Revisit Trigger

Revisit if Cloudflare Workers VPC/Containers prove equivalent private detonation controls with lower cost and operational risk.

