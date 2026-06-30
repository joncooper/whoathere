# Vault Architecture

## Summary

WhoaThere Vault is a registry-compatible proxy that enforces scan-before-serve admission for npm and PyPI artifacts. It separates serving, fetch, and detonation planes so developer/CI consumers never need direct public-registry egress.

## Data Flow

1. Client requests npm packument/tarball or PyPI Simple API/file through Vault.
2. Vault checks promoted metadata and digest-bound verdict.
3. Warm approved artifacts stream from promoted CAS.
4. Cache miss creates admission job and stores upstream data in quarantine CAS.
5. Scanner/detonator produces verdict.
6. Only `allow` promotes digest and generated metadata to serving namespace.
7. Deny/quarantine/manual-review states return deterministic package-manager-compatible errors.

## Planes

- Serving plane: authenticated registry-compatible endpoints, metadata rendering, artifact streaming, admission lookup.
- Fetch plane: controlled upstream egress to npm/PyPI and explicitly allowed mirrors.
- Detonation plane: isolated ephemeral execution with no internal network route and no reusable credentials.
- Control plane: policy, identity, overrides, audit, and admin workflows.

## Invariants

- Approval is bound to artifact digest, ecosystem, package metadata context, source, and policy version.
- Public upstream metadata is never served directly if it points clients at public artifact URLs.
- Quarantine and promoted namespaces are separate.
- Rollback never exposes unscanned artifacts or permissive public fallback.
- Break-glass is scoped, time-bound, revocable, and audited.

