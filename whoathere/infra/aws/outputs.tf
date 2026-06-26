output "vpc_id" {
  description = "Vault VPC id."
  value       = aws_vpc.vault.id
}

output "private_subnet_ids" {
  description = "Private data-plane subnet ids."
  value       = aws_subnet.private[*].id
}

output "egress_subnet_ids" {
  description = "Controlled egress subnet ids."
  value       = aws_subnet.egress[*].id
}

output "artifact_bucket_id" {
  description = "S3 bucket for content-addressed Vault artifacts."
  value       = aws_s3_bucket.artifacts.id
}

output "admission_queue_url" {
  description = "SQS admission workflow queue URL."
  value       = aws_sqs_queue.admission.url
}

output "vault_nlb_dns_name" {
  description = "Internal Network Load Balancer DNS name."
  value       = aws_lb.vault.dns_name
}

output "s3_endpoint_id" {
  description = "Gateway VPC endpoint id for private S3 access."
  value       = aws_vpc_endpoint.s3.id
}

output "sqs_endpoint_id" {
  description = "Interface VPC endpoint id for private SQS access."
  value       = aws_vpc_endpoint.sqs.id
}

output "phase_3_deferred_controls" {
  description = "Controls intentionally deferred from the local Phase 3 MVP skeleton."
  value = [
    "aurora_metadata_transactions",
    "ecs_service_definitions",
    "least_privilege_iam",
    "network_firewall_rule_groups",
    "privatelink_endpoint_service",
    "production_audit_sink",
    "real_upstream_fetch_worker",
  ]
}
