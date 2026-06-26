variable "aws_region" {
  description = "AWS region for the Phase 3 Vault MVP skeleton."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Name prefix for Vault resources."
  type        = string
  default     = "whoathere-vault"
}

variable "vpc_cidr" {
  description = "CIDR block for the Vault VPC."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "Availability zones for private and egress subnets."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "private_subnet_cidrs" {
  description = "Private data-plane subnet CIDRs."
  type        = list(string)
  default     = ["10.42.10.0/24", "10.42.11.0/24"]
}

variable "egress_subnet_cidrs" {
  description = "Controlled egress subnet CIDRs for future fetch workers."
  type        = list(string)
  default     = ["10.42.20.0/24", "10.42.21.0/24"]
}

variable "allowed_client_cidrs" {
  description = "Private CIDRs allowed to reach the Vault data-plane listener."
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "artifact_bucket_name" {
  description = "Optional explicit S3 artifact bucket name. Leave empty for provider-generated name."
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "CloudWatch log retention for Vault service logs."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Additional tags for Vault resources."
  type        = map(string)
  default     = {}
}
