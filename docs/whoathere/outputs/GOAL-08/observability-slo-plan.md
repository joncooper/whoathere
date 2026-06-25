# Observability And SLO Plan

## Service Indicators

| Area | Indicators |
| --- | --- |
| Warm cache | p50/p95/p99 latency, error rate, bytes streamed, digest mismatch. |
| Cold miss | admission latency by stage, queue age, scan time, detonation time. |
| Policy | decision latency, stale policy count, deny/warn/break-glass rates. |
| Endpoint | shim startup latency, sandbox startup, cleanup failures, bypass detections. |
| Audit | event write latency, delivery lag, retention failures. |

## Initial SLOs

- Warm metadata p95 under 150 ms regionally.
- Warm artifact first byte p95 under 250 ms regionally.
- Audit event durability p99 under 60 seconds.
- Detonation backlog alert if oldest item exceeds 15 minutes.
- Phase 3 must add p99, availability, error-budget, burn-rate alert, paging threshold, measurement window, and owner for every production SLO before launch.
- Cold miss has no fixed SLO until the minimum allow-verdict evidence profiles are benchmarked; CI should use prewarm for predictable builds.

## Dashboards

- Vault serving.
- Admission pipeline.
- Detonation fleet.
- Policy decisions.
- Endpoint health.
- Security incidents.
