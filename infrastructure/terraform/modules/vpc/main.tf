################################################################################
# VPC — 3 AZs, 5 Subnet Tiers: Public / Management / Private / Data / CDE
# Compliant with: CIS AWS Benchmark v2, HIPAA §164.312, PCI-DSS Req 1
################################################################################

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  # Subnet CIDR calculations from base VPC CIDR
  public_cidrs  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i)]
  mgmt_cidrs    = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 10, i + 10)]
  private_cidrs = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 6, i + 4)]
  data_cidrs    = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i + 20)]
  cde_cidrs     = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 10, i + 30)]
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = var.enable_dedicated_tenancy ? "dedicated" : "default"

  tags = { Name = "${var.name}-vpc" }
}

# Secondary CIDR for EKS pod networking
resource "aws_vpc_ipv4_cidr_block_association" "eks_pods" {
  count      = var.eks_pod_cidr != "" ? 1 : 0
  vpc_id     = aws_vpc.main.id
  cidr_block = var.eks_pod_cidr
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-igw" }
}

################################################################################
# Public Subnets — ALB, NAT Gateway, NLB
################################################################################
resource "aws_subnet" "public" {
  count                   = length(local.azs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false # Never auto-assign public IPs

  tags = {
    Name                                        = "${var.name}-public-${local.azs[count.index]}"
    "kubernetes.io/role/elb"                    = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    Tier                                        = "public"
  }
}

resource "aws_eip" "nat" {
  count  = length(local.azs)
  domain = "vpc"
  tags   = { Name = "${var.name}-nat-eip-${local.azs[count.index]}" }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_nat_gateway" "main" {
  count         = length(local.azs)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = { Name = "${var.name}-nat-${local.azs[count.index]}" }
  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-public-rt" }
}

resource "aws_route" "public_igw" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

################################################################################
# Management Subnets — Network Firewall, SSM, CloudHSM
################################################################################
resource "aws_subnet" "management" {
  count             = length(local.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.mgmt_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.name}-mgmt-${local.azs[count.index]}"
    Tier = "management"
  }
}

resource "aws_route_table" "management" {
  count  = length(local.azs)
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-mgmt-rt-${local.azs[count.index]}" }
}

resource "aws_route" "management_nat" {
  count                  = length(local.azs)
  route_table_id         = aws_route_table.management[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

resource "aws_route_table_association" "management" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.management[count.index].id
  route_table_id = aws_route_table.management[count.index].id
}

################################################################################
# Private Subnets — EKS Nodes, Application Layer
################################################################################
resource "aws_subnet" "private" {
  count             = length(local.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name                                        = "${var.name}-private-${local.azs[count.index]}"
    "kubernetes.io/role/internal-elb"           = "1"
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "karpenter.sh/discovery"                    = var.cluster_name
    Tier                                        = "private"
  }
}

resource "aws_route_table" "private" {
  count  = length(local.azs)
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-private-rt-${local.azs[count.index]}" }
}

resource "aws_route" "private_nat" {
  count                  = length(local.azs)
  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

resource "aws_route_table_association" "private" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

################################################################################
# Data Subnets — RDS Aurora, ElastiCache, OpenSearch (NO internet route)
################################################################################
resource "aws_subnet" "data" {
  count             = length(local.azs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.data_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.name}-data-${local.azs[count.index]}"
    Tier = "data"
  }
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-data-rt" }
  # No internet route — data tier is completely isolated
}

resource "aws_route_table_association" "data" {
  count          = length(local.azs)
  subnet_id      = aws_subnet.data[count.index].id
  route_table_id = aws_route_table.data.id
}

################################################################################
# CDE Subnets — PCI Cardholder Data Environment (ultra-isolated)
################################################################################
resource "aws_subnet" "cde" {
  count             = var.enable_cde ? length(local.azs) : 0
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.cde_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name                  = "${var.name}-cde-${local.azs[count.index]}"
    Tier                  = "cde"
    "pci:scope"           = "in-scope"
    "compliance:pci-dss"  = "true"
  }
}

resource "aws_route_table" "cde" {
  count  = var.enable_cde ? 1 : 0
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-cde-rt" }
  # Absolutely no internet route — payment processor only via static IP routes
}

resource "aws_route_table_association" "cde" {
  count          = var.enable_cde ? length(local.azs) : 0
  subnet_id      = aws_subnet.cde[count.index].id
  route_table_id = aws_route_table.cde[0].id
}

################################################################################
# VPC Flow Logs — ALL traffic (accepted + rejected)
################################################################################
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/flow-logs/${var.name}"
  retention_in_days = 400 # 13+ months for PCI DSS Req 10.7
  kms_key_id        = var.kms_key_arn

  tags = { Name = "${var.name}-vpc-flow-logs" }
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "${var.name}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = var.account_id
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.name}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup", "logs:CreateLogStream",
        "logs:PutLogEvents", "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  log_format = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flow-direction} $${traffic-path} $${log-status}"

  tags = { Name = "${var.name}-flow-log" }
}

# S3 flow log destination for long-term storage + Athena queries
resource "aws_flow_log" "s3" {
  count                    = var.flow_log_s3_bucket_arn != "" ? 1 : 0
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${var.flow_log_s3_bucket_arn}/vpc-flow-logs/"
  log_format               = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flow-direction} $${traffic-path} $${log-status}"
  destination_options {
    file_format                = "parquet"
    hive_compatible_partitions = true
    per_hour_partition         = true
  }
}

################################################################################
# VPC Endpoints — Keep ALL AWS API traffic within AWS backbone
################################################################################
resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.name}-vpce-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for VPC endpoints — allow HTTPS from within VPC only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS from VPC CIDR only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.name}-vpce-sg" }
}

locals {
  interface_endpoints = [
    "ecr.api", "ecr.dkr", "logs", "monitoring", "secretsmanager",
    "kms", "sts", "ssm", "ssmmessages", "ec2messages", "ec2",
    "elasticloadbalancing", "sqs", "sns", "lambda", "ecs",
    "ecs-agent", "ecs-telemetry", "states", "events",
    "xray", "codepipeline", "codebuild", "codeartifact.api",
    "macie2", "guardduty-data", "inspector2", "config",
    "auditmanager", "healthlake", "frauddetector",
    "acm-pca", "cloudhsmv2", "autoscaling"
  ]
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(local.interface_endpoints)

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = { Name = "${var.name}-vpce-${each.value}" }
}

# Gateway endpoints (free, no data processing charges)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(
    aws_route_table.private[*].id,
    aws_route_table.data[*].id,
    [aws_route_table.public.id]
  )
  tags = { Name = "${var.name}-vpce-s3" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(
    aws_route_table.private[*].id,
    aws_route_table.data[*].id
  )
  tags = { Name = "${var.name}-vpce-dynamodb" }
}

################################################################################
# Network ACLs — Defense in depth (SGs + NACLs)
################################################################################
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id

  # Inbound: HTTPS only from internet
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }
  # Inbound: HTTP for redirect (300)
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }
  # Inbound: Ephemeral ports for return traffic
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }
  # Explicit deny SSH from internet
  ingress {
    rule_no    = 50
    protocol   = "tcp"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }
  # Explicit deny RDP from internet
  ingress {
    rule_no    = 51
    protocol   = "tcp"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 3389
    to_port    = 3389
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.name}-public-nacl" }
}

resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  # Allow from VPC CIDR only
  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }
  # Allow return traffic from internet (via NAT)
  ingress {
    rule_no    = 200
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }
  # Explicit deny from internet directly
  ingress {
    rule_no    = 50
    protocol   = "tcp"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.name}-private-nacl" }
}

resource "aws_network_acl" "data" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.data[*].id

  # Only from private subnets CIDR
  dynamic "ingress" {
    for_each = local.private_cidrs
    content {
      rule_no    = 100 + ingress.key
      protocol   = "-1"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 0
      to_port    = 0
    }
  }
  # Deny all from internet
  ingress {
    rule_no    = 10
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "${var.name}-data-nacl" }
}

resource "aws_network_acl" "cde" {
  count      = var.enable_cde ? 1 : 0
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.cde[*].id

  # Deny all by default — only explicit allows
  ingress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  # Allow only from payment proxy subnet CIDR (configured per payment processor)
  dynamic "ingress" {
    for_each = var.payment_processor_cidrs
    content {
      rule_no    = 100 + ingress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 443
      to_port    = 443
    }
  }

  egress {
    rule_no    = 32766
    protocol   = "-1"
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  dynamic "egress" {
    for_each = var.payment_processor_cidrs
    content {
      rule_no    = 100 + egress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = egress.value
      from_port  = 443
      to_port    = 443
    }
  }

  tags = {
    Name               = "${var.name}-cde-nacl"
    "pci:scope"        = "in-scope"
    "compliance:pci"   = "true"
  }
}
