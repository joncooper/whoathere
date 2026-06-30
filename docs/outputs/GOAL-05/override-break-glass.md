# Override And Break-Glass

## Manual Review

Manual review can convert `manual_review` or `quarantine` to `allow` or `deny` for a specific artifact digest and policy context.

## Break-Glass

Break-glass is for urgent continuation when policy permits. It is:

- Scoped by tenant, project, package, version, digest, source, user/machine/CI, and command.
- Time-bound with maximum default of 120 minutes.
- Revocable.
- Audited at request, approval, use, expiry, and revocation.
- Not available for unaudited bypass, unknown artifact digest in CI, scanner/detonator failure for unknown digests, CAS/metadata mismatch, or public fallback.

## Hard Prohibitions

Break-glass cannot:

- Promote an unknown or unscanned artifact.
- Convert scanner or detonator infrastructure failure into `allow`.
- Create a durable allow verdict.
- Enable public registry/index fallback for protected namespaces.
- Suppress audit emission.
- Apply after expiry or revocation.

## Notifications

Security admins receive notifications for approval, use, expiry, and revocation.
