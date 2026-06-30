# WhoaThere Vault AWS MVP Skeleton

This directory is the Phase 3 AWS-first deployment artifact for the WhoaThere Vault MVP. It is intentionally a deployment skeleton, not a complete production module.

## Topology

- Private data-plane subnets host Vault services behind an internal Network Load Balancer.
- Private data-plane subnets have no default internet route.
- Controlled egress subnets host NAT gateways for future upstream fetch workers only.
- S3 stores content-addressed quarantine/promoted artifacts with KMS encryption and versioning.
- SQS models the admission/fetch/scanner workflow boundary.
- S3 and SQS access use VPC endpoints from the private plane.
- CloudWatch receives service logs.
- Security groups separate data-plane serving from worker egress.

## Security Defaults

- No public load balancer is defined.
- Local-dev loopback serving is not reused as an enterprise listener.
- Enterprise/non-loopback serving requires explicit auth material in the Rust boundary before protected routes are allowed.
- Public upstream fetch is still disabled in the Rust implementation; these network resources are for the future bounded fetch worker.
- Network Firewall rule groups, Aurora metadata transactions, ECS services, IAM least-privilege policies, and PrivateLink endpoint-service publication remain follow-on Phase 3 tasks.

## Validation

The required local closeout validation for the current Phase 3 goal is Rust-focused. Terraform provider downloads are not part of the local offline validation pass. Before using this skeleton in AWS, run:

```sh
terraform init
terraform validate
terraform plan
```

Do not deploy this skeleton as a production Vault until the deferred Phase 3 items in `docs/product-build-run/phase-3-enterprise-vault-checkpoint.md` are complete.
