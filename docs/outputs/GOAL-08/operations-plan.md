# Operations Plan

## Environments

- `dev`: internal testing with synthetic malicious fixtures.
- `staging`: production-like Vault, no customer secrets.
- `prod`: multi-AZ AWS deployment with strict change control.

## Deployment

- Infrastructure as code for AWS core.
- Separate serving, fetch, detonation, policy, and audit components.
- Blue/green or rolling deploys with health gates.
- Rollback restores previous approved metadata/verdict state only.

## Runbooks

- Vault outage.
- Scanner/detonator backlog.
- Policy-service outage.
- CAS integrity failure.
- False positive.
- Malicious package discovery.
- Key compromise.

## On-Call Signals

- Warm-cache latency/error rate.
- Cold-miss admission latency.
- Detonation queue age/depth.
- Policy decision failures.
- CAS digest mismatch.
- Break-glass usage.

