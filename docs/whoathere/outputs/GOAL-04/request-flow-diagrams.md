# Request Flow Diagrams

## Warm Cache Hit

```mermaid
sequenceDiagram
  participant C as Client
  participant V as Vault
  participant DB as Metadata DB
  participant S3 as Promoted CAS
  C->>V: GET metadata/artifact
  V->>DB: lookup active servable generation
  DB-->>V: generation + allow verdict + digest + metadata digest
  V->>V: verify policy/source/context/generation
  V->>S3: stream generation digest
  S3-->>V: verified bytes
  V-->>C: 200 package response
```

## Cache Miss

```mermaid
sequenceDiagram
  C->>V: package request
  V->>V: acquire admission lock
  V-->>C: 202/409-style deterministic pending or blocking wait
  V->>Fetch: fetch upstream
  Fetch->>CAS: write quarantine
  V->>Workers: scan/detonate
  Workers->>DB: evidence summary
  V->>DB: conditional verdict + servable_generation commit if allow
  V->>CAS: serve only after active generation verifies
```

## Policy Denial

Vault returns `403` with machine-readable reason, policy version, retryability false, and audit ID.

## Upstream Failure

Vault returns `503` retryable if upstream fetch failed before artifact admission; no public fallback is allowed.

## Rollback

Rollback points aliases to a last known approved servable generation only. Pending admissions remain pending or fail deterministic; unapproved upstream content is never exposed.
