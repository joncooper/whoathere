# WhoaThere Phase 3 Enterprise Vault Checkpoint

## Scope

Phase 3 turns the Vault prototype into an enterprise-shaped Vault data-plane MVP. It does not start Phase 4 dynamic detonation, and it does not relax Phase 1 or Phase 2 endpoint fail-closed gates.

The Phase 3 priority order is:

1. AWS-first private-network Vault deployment path.
2. npm and PyPI read compatibility from approved cache state.
3. Tenant/auth/readiness/audit boundaries before broader performance or admin polish.

## Phase 3 MVP Standard Used

The initial Phase 3 standard was sufficient for a credible MVP, but it was too broad if interpreted as full production deployment. The standard used for verification was narrowed to the smallest production-shaped MVP:

- Vault exposes a real HTTP service path for local development, not only one-shot simulations.
- Local-dev binds remain loopback-only and bounded by request/idle limits.
- Enterprise/non-loopback configuration is explicitly separate from local-dev and requires configured bearer-token auth material.
- Health and readiness are distinct; health can be up while protected-traffic readiness fails closed.
- npm and PyPI read paths serve only promoted/cache-approved fixture artifacts.
- Unknown, unpromoted, malformed, tenant-mismatched, cache-key-mismatched, or policy-denied reads fail closed before package bytes are served.
- Package bytes are content-addressed and hash-verified before promotion.
- Cache keys remain canonical, path-safe, and digest-bound.
- Admission evidence must bind the same tenant, artifact, digest, cache key, profile, fetch result, and request before promotion.
- Registry/index compatibility URLs must not point at public upstream registries.
- Request summaries and audit handles must not log authorization headers, request bodies, response bodies, raw package bytes, raw nonces, or local internal paths.
- Phase 3 deployment artifacts must select AWS as the MVP path and document the private-network topology, but full ECS/Aurora/S3/SQS production provisioning can remain a follow-on implementation task.
- Public upstream fetch and scanner/detonator execution remain disabled until their bounded, audited execution paths are implemented.

## Implemented Phase 3 Support

Phase 3 now provides:

- Bounded loopback Vault HTTP server for local compatibility testing.
- `/healthz` liveness and fail-closed `/readyz` protected-traffic readiness.
- Explicit enterprise HTTP options that require bearer-token auth before protected routes can serve.
- Enterprise bind configuration validation that rejects local-dev non-loopback binds and rejects enterprise binds without canonical `sha256:<64 lowercase hex>` token material.
- npm packument and tarball compatibility routes for deterministic safe fixture archives.
- PyPI Simple API and wheel-file compatibility routes for deterministic safe fixture archives.
- Tenant-aware registry route checks that deny mismatched tenant requests before metadata rendering or package-byte lookup.
- Exact promoted artifact plus cache-object-key lookup before package-byte responses.
- Package-byte `HEAD`, single byte range, ETag, immutable cache headers, binary-safe response rendering, and sanitized request summaries.
- Minimal serve/deny audit correlation headers for registry byte paths and tenant authorization denials.
- AWS-first Terraform skeleton under `whoathere/infra/aws/` for VPC, private data-plane subnets, controlled egress subnets, S3 CAS bucket, KMS, queue, log group, NLB, and security group boundaries.

## Security Posture

Phase 3 still does not authorize high-risk npm or pip execution. The endpoint remains fail closed unless Phase 2 can prove same-subject containment and Vault-only egress for the exact launch subject/context.

The Vault data-plane MVP is intentionally scan-before-serve shaped: artifacts can be served only after local admission evidence and verified fetch-result bindings produce a servable generation. Public upstream fetch execution, dynamic detonation, and production scanner worker execution remain disabled in this phase.

## Exit Criteria Evidence

| Exit criterion | Evidence |
| --- | --- |
| real HTTP service path exists while local-dev exposure stays safe | `serve_loopback_http`, `serve_loopback_listener`, loopback bind validation tests, and bounded server tests. |
| health and readiness are distinct and fail closed for protected traffic | `/healthz` remains 200; `/readyz` returns 503 with `protected_traffic_ready=false` until dependencies are verified. |
| enterprise/non-loopback mode requires auth posture | `VaultServeConfig`, `validate_vault_serve_config`, `VaultHttpOptions`, and enterprise auth route tests. |
| npm/PyPI compatibility serves only approved cache state | registry compatibility tests cover promoted metadata, fixture archive bytes, HEAD/range behavior, no public URLs, and unpromoted denial. |
| tenant separation is enforced before package bytes | tenant-mismatched registry metadata and tarball reads return 403 with no package bytes. |
| cache promotion is digest-bound | `InMemoryCacheStore` verifies payload SHA-256 before quarantine/promote and serves only exact artifact plus object key. |
| admission promotion requires complete same-subject evidence | `AdmissionController` tests cover missing fetch, mismatched fetch, profile mismatch, duplicate evidence, subject mismatch, and no-promotion failure states. |
| audit/log output avoids secrets and payloads | sanitized request summaries omit bodies; challenge-authority audit omits raw nonces and paths; registry byte routes emit correlation headers without package bytes. |
| AWS MVP path is selected and represented | `whoathere/infra/aws/` contains the AWS-first topology skeleton and deployment notes. |
| Phase 1/2 high-risk execution remains fail closed | Full workspace tests continue to cover source/protect/launch fail-closed behavior. |

## Deferred To Later Phase 3 Work

- Durable PostgreSQL/Aurora metadata transactions.
- Durable S3 object storage wiring behind the Rust data plane.
- ECS/Fargate service definitions, IAM policies, image build/publish, and runtime secret injection.
- Network Firewall rule groups and full egress inspection implementation.
- Production auth integration with customer IdP or workload identity.
- Production audit sink, retention policy, export/delete APIs, and tamper evidence.
- Warm-cache 1,000 concurrent CI benchmark against a deployed service.
- npm/pip client compatibility tests against the deployed service.

## Deferred To Phase 4

- Dynamic detonation workers for install/build/import behavior.
- Behavior analysis automation.
- Real scanner/detonator worker execution against untrusted artifacts.
- Admin review workflows beyond local-dev audit and deployment skeletons.

## Phase 3 Closeout Validation

Focused checks:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-vault-dev
```

Final validation:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
rg -n "[^[:ascii:]]" README.md docs/product-build-run scripts whoathere/README.md whoathere/Cargo.toml whoathere/Cargo.lock whoathere/crates whoathere/examples whoathere/tests whoathere/probe-images
```

Result: all required Rust validation passed on this tree. The ASCII scan produced no matches. Terraform was not available in this environment, so the AWS skeleton was reviewed locally but not `terraform validate` checked here.
