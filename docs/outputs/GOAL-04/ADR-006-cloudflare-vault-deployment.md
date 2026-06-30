# ADR-006: Cloudflare Vault Deployment

- Status: rejected as sole production system for MVP
- Date: 2026-06-25

## Context

Cloudflare provides Workers, R2, Cache, Queues, Workflows, Containers, Tunnel, and Zero Trust features attractive for global delivery.

## Decision

Do not use Cloudflare as the sole system of record for MVP Vault. Use it as an optional edge, Zero Trust, or cache layer in the hybrid architecture after AWS source-of-truth semantics are established.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Workers + R2 + Containers as full Vault | Private network/detonation controls and Workers VPC maturity are higher risk for MVP. |
| Workers Cache as approval cache | Cache API locality and eviction mean it cannot be authoritative. |
| Cloudflare-only metadata and audit | Risk of split operational semantics without mature VPC isolation. |

## Authority Boundaries

In Cloudflare-only mode, Cloudflare would own secrets, R2 CAS, D1/KV metadata, verdicts, policy, audit, evidence, and deployment state. This is rejected for MVP because detonation and private-network controls are less mature than AWS.

## Security Impact

Strong edge access controls but weaker default fit for isolated package detonation and customer VPC-private consumption.

## Operational Impact

Simpler edge operations, but product would need to design around platform limits and beta private connectivity.

## Compatibility Impact

Good global access, less direct enterprise VPC isolation.

## Cost/Performance Impact

Attractive egress economics and edge latency. Not sufficient to outweigh detonation/private-network risk for MVP.

## Revisit Trigger

Revisit when Workers VPC/private routing and Containers meet detonation isolation requirements in production and benchmarked workloads.

