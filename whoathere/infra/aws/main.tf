terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  tags = merge(var.tags, {
    Application = "whoathere-vault"
    Phase       = "phase-3-mvp"
  })
}

resource "aws_vpc" "vault" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-vpc"
  })
}

resource "aws_internet_gateway" "egress" {
  vpc_id = aws_vpc.vault.id

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-egress-igw"
  })
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.vault.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-private-${count.index + 1}"
    Plane = "data"
  })
}

resource "aws_subnet" "egress" {
  count             = length(var.egress_subnet_cidrs)
  vpc_id            = aws_vpc.vault.id
  cidr_block        = var.egress_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-egress-${count.index + 1}"
    Plane = "egress"
  })
}

resource "aws_route_table" "egress" {
  vpc_id = aws_vpc.vault.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.egress.id
  }

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-egress-rt"
  })
}

resource "aws_route_table_association" "egress" {
  count          = length(aws_subnet.egress)
  subnet_id      = aws_subnet.egress[count.index].id
  route_table_id = aws_route_table.egress.id
}

resource "aws_eip" "nat" {
  count  = length(aws_subnet.egress)
  domain = "vpc"

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-nat-${count.index + 1}"
  })
}

resource "aws_nat_gateway" "fetch" {
  count         = length(aws_subnet.egress)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.egress[count.index].id

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-fetch-nat-${count.index + 1}"
  })
}

resource "aws_route_table" "private" {
  count  = length(aws_subnet.private)
  vpc_id = aws_vpc.vault.id

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-private-rt-${count.index + 1}"
  })
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_kms_key" "vault" {
  description             = "WhoaThere Vault Phase 3 MVP key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = local.tags
}

resource "aws_s3_bucket" "artifacts" {
  bucket = var.artifact_bucket_name == "" ? null : var.artifact_bucket_name

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-artifacts"
  })
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.vault.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_sqs_queue" "admission" {
  name                       = "${var.name_prefix}-admission"
  kms_master_key_id           = aws_kms_key.vault.arn
  visibility_timeout_seconds = 300

  tags = local.tags
}

resource "aws_cloudwatch_log_group" "vault" {
  name              = "/whoathere/${var.name_prefix}/vault"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.vault.arn

  tags = local.tags
}

resource "aws_security_group" "data_plane" {
  name        = "${var.name_prefix}-data-plane"
  description = "Vault data-plane ingress from private clients only"
  vpc_id      = aws_vpc.vault.id

  ingress {
    description = "Private npm and PyPI client traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_client_cidrs
  }

  egress {
    description     = "Data plane to internal workers and dependencies"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.workers.id]
  }

  tags = local.tags
}

resource "aws_security_group" "workers" {
  name        = "${var.name_prefix}-workers"
  description = "Vault workers with controlled egress"
  vpc_id      = aws_vpc.vault.id

  egress {
    description = "Bounded HTTPS egress for future fetch workers"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}

resource "aws_security_group" "vpc_endpoints" {
  name        = "${var.name_prefix}-vpc-endpoints"
  description = "Vault private AWS service endpoints"
  vpc_id      = aws_vpc.vault.id

  ingress {
    description     = "Data plane to private AWS endpoints"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.data_plane.id, aws_security_group.workers.id]
  }

  tags = local.tags
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.vault.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-s3-endpoint"
  })
}

resource "aws_vpc_endpoint" "sqs" {
  vpc_id              = aws_vpc.vault.id
  service_name        = "com.amazonaws.${var.aws_region}.sqs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-sqs-endpoint"
  })
}

resource "aws_lb" "vault" {
  name               = "${var.name_prefix}-vault"
  internal           = true
  load_balancer_type = "network"
  subnets            = aws_subnet.private[*].id

  tags = local.tags
}

resource "aws_lb_target_group" "data_plane" {
  name        = "${var.name_prefix}-data"
  port        = 443
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.vault.id

  health_check {
    enabled  = true
    protocol = "TCP"
  }

  tags = local.tags
}

resource "aws_lb_listener" "vault" {
  load_balancer_arn = aws_lb.vault.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.data_plane.arn
  }
}
