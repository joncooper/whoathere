# Incident Response Plan

## Malicious Package

1. Quarantine digest and affected metadata.
2. Deny future requests.
3. Identify tenants/projects that consumed artifact.
4. Notify customers with evidence summary.
5. Publish detection rule.
6. Review false-negative cause.

## False Positive

1. Manual review evidence.
2. Approve digest only if safe.
3. Publish corrected rule/policy.
4. Notify affected customers.
5. Record audit trail.

## Vault Outage

1. Preserve fail-closed semantics for CI.
2. Serve previous approved state only if safe.
3. Communicate status and retry guidance.
4. Audit break-glass use.

## Policy Misconfiguration

1. Freeze policy rollout.
2. Roll back signed policy version.
3. Audit impacted decisions.
4. Notify affected admins.

## Key Compromise

Follow GOAL-04 `secret-key-dr-plan.md`; freeze promotion, rotate keys, verify CAS, and notify affected customers.

## Launch-Ready Runbook Requirements

Before enterprise launch, define SEV levels, incident commander role, escalation contacts, customer notification triggers and SLAs, package revocation workflow, promotion freeze workflow, rollback criteria, evidence handling rules, and drill pass/fail criteria.
