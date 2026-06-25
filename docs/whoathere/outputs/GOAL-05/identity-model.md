# Identity Model

## Hierarchy

```text
tenant
  project
    repository
    policy set
    CI runner identities
    machine identities
```

## Identity Types

- User: local developer or admin.
- Machine: endpoint installation with generated keypair.
- CI runner: workload identity from CI provider or issued service token.
- Service account: Vault component identity.
- Admin approver: identity authorized for manual review and break-glass.

## Trust Requirements

- Endpoint enrolls machine identity and receives signed policy snapshots.
- CI uses short-lived tokens scoped to tenant/project/repository.
- Service-to-service auth uses mTLS or signed tokens with least privilege.
- Policy provenance is signed and versioned.
- Offline mode uses cached policy only within validity TTL.

## Break-Glass Authority

Break-glass requires actor, approver where configured, reason, scope, expiry, and revocation path. It never creates a durable allow rule.

