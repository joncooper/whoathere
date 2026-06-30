# Performance Plan

## Targets

| Path | Target |
| --- | --- |
| Warm metadata p95 | under 150 ms regional AWS |
| Warm artifact first byte p95 | under 250 ms regional AWS |
| Warm artifact error rate | under 0.1% |
| 1,000 concurrent CI warm jobs | no more than 1% throttled/retryable responses |
| Cold miss | measured by package class; no fixed SLO until detonation matrix benchmarked |

## Benchmarks

- PT-001: 1,000 concurrent CI jobs with realistic npm/pip dependency graph.
- PT-002: large tarball/wheel streaming without full buffering.
- PT-003: cold miss fetch, scan, detonation, promotion.
- PT-004: metadata fanout for large dependency tree.

## Capacity Model

- Metadata DB scales on read-heavy packument/Simple API lookups.
- Artifact streaming uses object-store range/stream APIs and backpressure.
- Admission queues are isolated from warm serving path.
- Detonation workers scale independently with queue depth.

## Pass/Fail

Fail if warm-cache tests require public fallback, full in-memory artifact buffering, stale unapproved metadata, or cache entries without digest/verdict validation.

