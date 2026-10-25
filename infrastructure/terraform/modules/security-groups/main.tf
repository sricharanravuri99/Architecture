################################################################################
# Security Groups — Least-Privilege, No Implicit Trust
# All SGs: deny-all default (AWS default), explicit allow only
# Compliant with: CIS AWS 5.x, PCI-DSS Req 1.3
################################################################################

# ALB — HTTPS from internet only
resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  vpc_id      = var.vpc_id
  description = "ALB: inbound HTTPS from internet; outbound to app SG only"

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTP for redirect (returns 301)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description              = "To app tier only"
    from_port                = 8080
    to_port                  = 8443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-alb-sg" }
}

# EKS Nodes / App tier
resource "aws_security_group" "app" {
  name_prefix = "${var.name}-app-"
  vpc_id      = var.vpc_id
  description = "App/EKS nodes: inbound from ALB only; outbound to data + VPC endpoints"

  ingress {
    description              = "From ALB only"
    from_port                = 8080
    to_port                  = 8443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.alb.id
  }
  ingress {
    description = "Node-to-node (EKS cluster CIDR)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }
  # Allow EKS control plane to reach nodes
  ingress {
    description              = "EKS control plane"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.eks_control_plane.id
  }
  ingress {
    description              = "EKS control plane kubelet"
    from_port                = 10250
    to_port                  = 10250
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.eks_control_plane.id
  }

  egress {
    description              = "To RDS"
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.rds.id
  }
  egress {
    description              = "To ElastiCache Redis"
    from_port                = 6379
    to_port                  = 6379
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.elasticache.id
  }
  egress {
    description              = "To OpenSearch"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.opensearch.id
  }
  egress {
    description              = "To VPC endpoints (AWS services)"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = var.vpc_endpoint_sg_id
  }
  egress {
    description = "NAT for internet-bound traffic (updates, etc.)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-app-sg" }
}

# EKS Control Plane
resource "aws_security_group" "eks_control_plane" {
  name_prefix = "${var.name}-eks-cp-"
  vpc_id      = var.vpc_id
  description = "EKS control plane: managed nodes communication"

  ingress {
    description              = "From nodes — HTTPS API"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }

  egress {
    description              = "To nodes — kubelet, kube-proxy"
    from_port                = 1025
    to_port                  = 65535
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }
  egress {
    description              = "To nodes — kubelet"
    from_port                = 10250
    to_port                  = 10250
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-eks-cp-sg" }
}

# RDS Aurora — data tier
resource "aws_security_group" "rds" {
  name_prefix = "${var.name}-rds-"
  vpc_id      = var.vpc_id
  description = "RDS Aurora: inbound PostgreSQL from app SG and RDS Proxy SG only"

  ingress {
    description              = "PostgreSQL from app tier"
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }
  ingress {
    description              = "PostgreSQL from RDS Proxy"
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.rds_proxy.id
  }

  # NO egress — deny all outbound (database never initiates connections)
  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-rds-sg" }
}

# RDS Proxy
resource "aws_security_group" "rds_proxy" {
  name_prefix = "${var.name}-rds-proxy-"
  vpc_id      = var.vpc_id
  description = "RDS Proxy: accept from app, forward to RDS"

  ingress {
    description              = "From app tier"
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }
  egress {
    description              = "To RDS"
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.rds.id
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-rds-proxy-sg" }
}

# ElastiCache Redis
resource "aws_security_group" "elasticache" {
  name_prefix = "${var.name}-cache-"
  vpc_id      = var.vpc_id
  description = "ElastiCache Redis: TLS-only from app SG"

  ingress {
    description              = "Redis TLS from app tier"
    from_port                = 6379
    to_port                  = 6379
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-cache-sg" }
}

# OpenSearch
resource "aws_security_group" "opensearch" {
  name_prefix = "${var.name}-opensearch-"
  vpc_id      = var.vpc_id
  description = "OpenSearch: HTTPS from app tier and monitoring"

  ingress {
    description              = "HTTPS from app tier"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }
  ingress {
    description              = "Node-to-node"
    from_port                = 9300
    to_port                  = 9300
    protocol                 = "tcp"
    self                     = true
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-opensearch-sg" }
}

# CloudHSM
resource "aws_security_group" "cloudhsm" {
  name_prefix = "${var.name}-cloudhsm-"
  vpc_id      = var.vpc_id
  description = "CloudHSM: client comms from app only; cluster internal"

  ingress {
    description              = "HSM client from app"
    from_port                = 2223
    to_port                  = 2225
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }
  ingress {
    description = "HSM cluster-internal sync"
    from_port   = 2225
    to_port     = 2225
    protocol    = "tcp"
    self        = true
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-cloudhsm-sg" }
}

# CDE — Cardholder Data Environment (PCI ultra-isolated)
resource "aws_security_group" "cde" {
  count       = var.enable_cde ? 1 : 0
  name_prefix = "${var.name}-cde-"
  vpc_id      = var.vpc_id
  description = "CDE: accept ONLY from payment proxy on PCI port; no 0.0.0.0/0"

  ingress {
    description              = "From payment proxy SG only"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.payment_proxy[0].id
  }

  egress {
    description = "To payment processor IPs only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.payment_processor_cidrs
  }

  lifecycle { create_before_destroy = true }
  tags = {
    Name         = "${var.name}-cde-sg"
    "pci:scope"  = "in-scope"
    Compliance   = "PCI-DSS"
  }
}

# Payment Proxy (sits between app and CDE)
resource "aws_security_group" "payment_proxy" {
  count       = var.enable_cde ? 1 : 0
  name_prefix = "${var.name}-pay-proxy-"
  vpc_id      = var.vpc_id
  description = "Payment proxy: receives tokenization requests from app"

  ingress {
    description              = "From app tier"
    from_port                = 8443
    to_port                  = 8443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.app.id
  }
  egress {
    description              = "To CDE"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.cde[0].id
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-payment-proxy-sg" }
}

# Lambda functions
resource "aws_security_group" "lambda" {
  name_prefix = "${var.name}-lambda-"
  vpc_id      = var.vpc_id
  description = "Lambda: no inbound; outbound to VPC endpoints and data tier"

  egress {
    description              = "To VPC endpoints"
    from_port                = 443
    to_port                  = 443
    protocol                 = "tcp"
    source_security_group_id = var.vpc_endpoint_sg_id
  }
  egress {
    description              = "To RDS"
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.rds.id
  }
  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-lambda-sg" }
}
