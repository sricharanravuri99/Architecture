################################################################################
# Production Environment — Orchestrates all modules
# Multi-region: us-east-1 (primary) + us-west-2 (DR)
# Compliance: HIPAA, PCI-DSS, SOX, NIST 800-53, CIS AWS 2.x
################################################################################

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.40"
      configuration_aliases = [aws.dr]
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.27"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
  }

  backend "s3" {
    bucket         = "myapp-terraform-state-production"
    key            = "environments/production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    kms_key_id     = "alias/terraform-state-key"
    dynamodb_table = "myapp-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project         = var.project_name
      Environment     = "production"
      ManagedBy       = "terraform"
      Owner           = var.owner
      CostCenter      = var.cost_center
      DataClassification = "Sensitive"
      Backup          = "true"
    }
  }
}

provider "aws" {
  alias  = "dr"
  region = var.dr_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = "production-dr"
      ManagedBy   = "terraform"
      Role        = "DR"
    }
  }
}

################################################################################
# CloudHSM (must be first — KMS depends on it)
################################################################################

module "cloudhsm" {
  source = "../../modules/cloudhsm"

  name                         = var.name
  hsm_subnet_ids               = module.vpc.management_subnet_ids
  key_store_password           = var.cloudhsm_key_store_password
  hsm_trust_anchor_certificate = var.cloudhsm_trust_anchor_cert
  security_sns_arn             = aws_sns_topic.security.arn
}

################################################################################
# KMS — Multi-tier key hierarchy
################################################################################

module "kms" {
  source = "../../modules/kms"

  name                       = var.name
  aws_region                 = var.aws_region
  phi_custom_key_store_id    = module.cloudhsm.custom_key_store_id
  pan_custom_key_store_id    = module.cloudhsm.custom_key_store_id
  security_admin_role_arn    = module.iam.break_glass_role_arn
  cde_principal_arns         = var.cde_principal_arns
  cloudtrail_trail_name      = "${var.name}-org-trail"
}

################################################################################
# VPC — 5-tier subnet architecture
################################################################################

module "vpc" {
  source = "../../modules/vpc"

  name                    = var.name
  aws_region              = var.aws_region
  vpc_cidr                = var.vpc_cidr
  availability_zones      = var.availability_zones
  public_subnet_cidrs     = var.public_subnet_cidrs
  management_subnet_cidrs = var.management_subnet_cidrs
  private_subnet_cidrs    = var.private_subnet_cidrs
  data_subnet_cidrs       = var.data_subnet_cidrs
  cde_subnet_cidrs        = var.cde_subnet_cidrs
  payment_processor_cidrs = var.payment_processor_cidrs
  flow_logs_kms_key_arn   = module.kms.cloudtrail_key_arn
}

################################################################################
# Security Groups
################################################################################

module "security_groups" {
  source = "../../modules/security-groups"

  name                    = var.name
  vpc_id                  = module.vpc.vpc_id
  app_sg_cidr             = var.private_subnet_cidrs
  payment_processor_cidrs = var.payment_processor_cidrs
}

################################################################################
# Network Firewall
################################################################################

module "network_firewall" {
  source = "../../modules/network-firewall"

  name                = var.name
  vpc_id              = module.vpc.vpc_id
  firewall_subnet_ids = module.vpc.public_subnet_ids
  kms_key_arn         = module.kms.cloudtrail_key_arn
  allowed_domains     = var.allowed_egress_domains
}

################################################################################
# EKS Cluster
################################################################################

module "eks" {
  source = "../../modules/eks"

  name                        = var.name
  cluster_version             = var.eks_cluster_version
  private_subnet_ids          = module.vpc.private_subnet_ids
  cluster_sg_id               = module.security_groups.eks_cluster_sg_id
  node_sg_id                  = module.security_groups.eks_node_sg_id
  kms_key_arn                 = module.kms.eks_key_arn
  cluster_admins              = var.eks_cluster_admins
  karpenter_node_role_arn     = module.eks.karpenter_node_role_arn
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_ca_cert)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_ca_cert)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

################################################################################
# IAM — IRSA, Permission Boundaries, Break-Glass
################################################################################

module "iam" {
  source = "../../modules/iam"

  name                    = var.name
  eks_oidc_provider_arn   = module.eks.oidc_provider_arn
  eks_oidc_provider       = module.eks.oidc_provider
  app_namespace           = var.app_namespace
  app_kms_key_arns        = [module.kms.app_key_arn, module.kms.secrets_key_arn]
  security_admin_arns     = var.security_admin_arns
  break_glass_external_id = var.break_glass_external_id
  security_sns_arn        = aws_sns_topic.security.arn
  is_organization         = var.is_organization
}

################################################################################
# Aurora PostgreSQL — Primary Database
################################################################################

module "rds" {
  source = "../../modules/rds-aurora"

  name                   = var.name
  vpc_id                 = module.vpc.vpc_id
  data_subnet_ids        = module.vpc.data_subnet_ids
  db_sg_id               = module.security_groups.rds_sg_id
  kms_key_arn            = module.kms.rds_key_arn
  database_name          = var.database_name
  performance_insights_kms_key_arn = module.kms.rds_key_arn
}

################################################################################
# ElastiCache Redis
################################################################################

module "elasticache" {
  source = "../../modules/elasticache"

  name             = var.name
  kms_key_arn      = module.kms.app_key_arn
  auth_token       = var.redis_auth_token
  redis_sg_id      = module.security_groups.redis_sg_id
  data_subnet_ids  = module.vpc.data_subnet_ids
  log_group_name   = "/aws/elasticache/${var.name}"
  alarm_sns_arn    = aws_sns_topic.alarms.arn
}

################################################################################
# OpenSearch
################################################################################

module "opensearch" {
  source = "../../modules/opensearch"

  name              = var.name
  kms_key_arn       = module.kms.app_key_arn
  opensearch_sg_id  = module.security_groups.opensearch_sg_id
  data_subnet_ids   = module.vpc.data_subnet_ids
  master_user_arn   = module.iam.break_glass_role_arn
  allowed_iam_arns  = [module.iam.app_backend_role_arn]
  alarm_sns_arn     = aws_sns_topic.alarms.arn
}

################################################################################
# DynamoDB Tables
################################################################################

module "dynamodb" {
  source = "../../modules/dynamodb"

  name           = var.name
  dr_kms_key_arn = var.dr_kms_key_arn
  alarm_sns_arn  = aws_sns_topic.alarms.arn

  tables = {
    sessions = {
      hash_key        = "session_id"
      kms_key_arn     = module.kms.app_key_arn
      streams_enabled = false
      ttl_attribute   = "expires_at"
      attributes = [{ name = "session_id", type = "S" }]
      tags = { DataClassification = "Sensitive" }
    }
    audit_log = {
      hash_key        = "resource_id"
      range_key       = "timestamp"
      kms_key_arn     = module.kms.app_key_arn
      global_table    = true
      streams_enabled = true
      attributes = [
        { name = "resource_id", type = "S" },
        { name = "timestamp",   type = "S" }
      ]
      tags = { DataClassification = "Audit", Backup = "true" }
    }
    patients = {
      hash_key        = "patient_id"
      kms_key_arn     = module.kms.phi_key_arn
      streams_enabled = true
      global_table    = true
      gsi = [{
        name            = "organization-index"
        hash_key        = "organization_id"
        projection_type = "KEYS_ONLY"
      }]
      attributes = [
        { name = "patient_id",      type = "S" },
        { name = "organization_id", type = "S" }
      ]
      tags = { DataClassification = "PHI", Backup = "true" }
    }
  }
}

################################################################################
# S3 Buckets
################################################################################

module "s3" {
  source = "../../modules/s3"

  name           = var.name
  dr_kms_key_arn = var.dr_kms_key_arn

  buckets = {
    assets = {
      purpose             = "static-assets"
      kms_key_arn         = module.kms.app_key_arn
      versioning          = true
      object_lock         = false
      replication_enabled = true
    }
    phi-data = {
      purpose             = "phi"
      kms_key_arn         = module.kms.phi_key_arn
      versioning          = true
      object_lock         = true
      object_lock_days    = 2555
      replication_enabled = true
      tags = { DataClassification = "PHI", HIPAAScope = "true" }
    }
    reports = {
      purpose             = "compliance-reports"
      kms_key_arn         = module.kms.app_key_arn
      versioning          = true
      object_lock         = true
      object_lock_days    = 2555
      replication_enabled = true
    }
    canary-artifacts = {
      purpose             = "synthetics-canary"
      kms_key_arn         = module.kms.app_key_arn
      versioning          = false
      object_lock         = false
      replication_enabled = false
    }
  }
}

################################################################################
# ECR Repositories
################################################################################

module "ecr" {
  source = "../../modules/ecr"

  name              = var.name
  kms_key_arn       = module.kms.app_key_arn
  allowed_pull_arns = [module.eks.node_role_arn, module.iam.app_backend_role_arn]
  dr_region         = var.dr_region

  repositories = {
    backend     = { max_image_count = 50 }
    frontend    = { max_image_count = 30 }
    worker      = { max_image_count = 30 }
    migration   = { max_image_count = 10 }
  }
}

################################################################################
# WAF
################################################################################

module "waf" {
  source = "../../modules/waf"

  name                = var.name
  scope               = "REGIONAL"
  rate_limit_per_5min = 2000
  enable_bot_control  = true
  allowed_countries   = var.allowed_countries
  log_destination_arn = aws_kinesis_firehose_delivery_stream.waf_logs.arn
  alb_arn             = aws_lb.main.arn
}

module "waf_cloudfront" {
  source    = "../../modules/waf"
  providers = { aws = aws.us_east_1 }

  name                = "${var.name}-cf"
  scope               = "CLOUDFRONT"
  rate_limit_per_5min = 2000
  enable_bot_control  = true
  allowed_countries   = var.allowed_countries
  log_destination_arn = aws_kinesis_firehose_delivery_stream.waf_logs.arn
}

################################################################################
# CloudFront
################################################################################

module "cloudfront" {
  source = "../../modules/cloudfront"

  name                       = var.name
  s3_bucket_regional_domain  = "${module.s3.bucket_ids["assets"]}.s3.${var.aws_region}.amazonaws.com"
  alb_dns_name               = aws_lb.main.dns_name
  waf_web_acl_arn            = module.waf_cloudfront.web_acl_arn
  acm_certificate_arn        = var.cloudfront_acm_cert_arn
  cloudfront_origin_secret   = var.cloudfront_origin_secret
  log_bucket_name            = module.s3.bucket_ids["reports"]
  domain_aliases             = var.domain_aliases
  domain_name                = var.domain_name
  allowed_countries          = var.allowed_countries
  route53_zone_id            = var.route53_zone_id
}

################################################################################
# Cognito
################################################################################

module "cognito" {
  source = "../../modules/cognito"

  name                     = var.name
  app_name                 = var.app_name
  domain_name              = var.domain_name
  cognito_subdomain        = "auth.${var.domain_name}"
  ses_from_email           = var.ses_from_email
  ses_arn                  = var.ses_arn
  acm_certificate_arn      = var.cognito_acm_cert_arn
  smart_fhir_callback_urls = var.smart_fhir_callback_urls
  smart_fhir_logout_urls   = var.smart_fhir_logout_urls
  authenticated_role_arn   = module.iam.app_backend_role_arn
}

################################################################################
# GuardDuty
################################################################################

module "guardduty" {
  source = "../../modules/guardduty"

  name                       = var.name
  security_sns_arn           = aws_sns_topic.security.arn
  ir_step_function_arn       = aws_sfn_state_machine.ec2_ir.arn
  custom_threat_intel_s3_uri = var.custom_threat_intel_s3_uri
}

################################################################################
# Security Hub
################################################################################

module "security_hub" {
  source = "../../modules/security-hub"

  name             = var.name
  security_sns_arn = aws_sns_topic.security.arn
  is_delegated_admin = var.is_security_hub_delegated_admin
}

################################################################################
# CloudTrail
################################################################################

module "cloudtrail" {
  source = "../../modules/cloudtrail"

  name                   = var.name
  cloudtrail_kms_key_arn = module.kms.cloudtrail_key_arn
  security_sns_arn       = aws_sns_topic.security.arn
  is_organization_trail  = var.is_organization
  log_retention_days     = 2555
}

################################################################################
# Config Rules
################################################################################

module "config" {
  source = "../../modules/config-rules"

  name              = var.name
  config_kms_key_arn = module.kms.cloudtrail_key_arn
  security_sns_arn  = aws_sns_topic.security.arn
}

################################################################################
# Monitoring
################################################################################

module "monitoring" {
  source = "../../modules/monitoring"

  name                  = var.name
  cluster_name          = module.eks.cluster_name
  kms_key_arn           = module.kms.app_key_arn
  eks_oidc_provider_arn = module.eks.oidc_provider_arn
  eks_oidc_provider     = module.eks.oidc_provider
  private_subnet_ids    = module.vpc.private_subnet_ids
  grafana_sg_id         = module.security_groups.monitoring_sg_id
  canary_sg_id          = module.security_groups.lambda_sg_id
  canary_bucket_name    = module.s3.bucket_ids["canary-artifacts"]
  alarm_sns_arn         = aws_sns_topic.alarms.arn
  pagerduty_endpoint    = var.pagerduty_endpoint
}

################################################################################
# Backup
################################################################################

module "backup" {
  source = "../../modules/backup"

  name               = var.name
  kms_key_arn        = module.kms.app_key_arn
  dr_kms_key_arn     = var.dr_kms_key_arn
  backup_sns_arn     = aws_sns_topic.alarms.arn
  report_bucket_name = module.s3.bucket_ids["reports"]

  critical_resource_arns = [
    module.rds.cluster_arn,
    module.dynamodb.table_arns["patients"],
    module.dynamodb.table_arns["audit_log"],
    module.s3.bucket_arns["phi-data"]
  ]
}

################################################################################
# SNS Topics (shared across modules)
################################################################################

resource "aws_sns_topic" "security" {
  name              = "${var.name}-security-alerts"
  kms_master_key_id = module.kms.app_key_arn
  tags              = { Name = "${var.name}-security", Purpose = "Security" }
}

resource "aws_sns_topic" "alarms" {
  name              = "${var.name}-operational-alarms"
  kms_master_key_id = module.kms.app_key_arn
  tags              = { Name = "${var.name}-alarms", Purpose = "Operations" }
}

resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.security.arn
  protocol  = "email"
  endpoint  = var.security_team_email
}

################################################################################
# WAF Logs → Kinesis Firehose → S3 (required format for WAF v2)
################################################################################

resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "aws-waf-logs-${var.name}"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose.arn
    bucket_arn         = module.s3.bucket_arns["reports"]
    prefix             = "waf-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "waf-errors/!{firehose:error-output-type}/"
    buffering_size     = 64
    buffering_interval = 300
    compression_format = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/${var.name}-waf"
      log_stream_name = "S3Delivery"
    }
  }

  server_side_encryption {
    enabled  = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = module.kms.app_key_arn
  }

  tags = { Name = "${var.name}-waf-logs" }
}

resource "aws_iam_role" "firehose" {
  name = "${var.name}-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "firehose" {
  name = "${var.name}-firehose-policy"
  role = aws_iam_role.firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"]
        Resource = [module.s3.bucket_arns["reports"], "${module.s3.bucket_arns["reports"]}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = [module.kms.app_key_arn]
      }
    ]
  })
}

################################################################################
# Application Load Balancer
################################################################################

resource "aws_lb" "main" {
  name               = "${var.name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [module.security_groups.alb_sg_id]
  subnets            = module.vpc.public_subnet_ids

  enable_deletion_protection = true
  enable_http2               = true
  drop_invalid_header_fields = true

  access_logs {
    bucket  = module.s3.bucket_ids["reports"]
    prefix  = "alb-logs"
    enabled = true
  }

  tags = { Name = "${var.name}-alb" }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_acm_cert_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.eks.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_target_group" "eks" {
  name        = "${var.name}-eks-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "ip"

  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
    matcher             = "200"
  }
}

################################################################################
# Step Functions — IR Playbook (EC2 Compromise)
################################################################################

resource "aws_sfn_state_machine" "ec2_ir" {
  name     = "${var.name}-ec2-ir-playbook"
  role_arn = aws_iam_role.sfn_ir.arn

  definition = jsonencode({
    Comment = "EC2 Incident Response Playbook — Isolate, Snapshot, Investigate"
    StartAt = "ParseFinding"
    States = {
      ParseFinding = {
        Type = "Pass"
        Parameters = {
          "instanceId.$"  = "$.detail.resource.instanceDetails.instanceId"
          "findingId.$"   = "$.detail.id"
          "severity.$"    = "$.detail.severity"
          "findingType.$" = "$.detail.type"
        }
        Next = "IsolateInstance"
      }
      IsolateInstance = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = "${var.name}-isolate-ec2"
          "Payload.$"  = "$"
        }
        Next           = "CreateForensicSnapshot"
        Catch = [{ ErrorEquals = ["States.ALL"], Next = "NotifySecurityTeam" }]
      }
      CreateForensicSnapshot = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = "${var.name}-snapshot-ec2"
          "Payload.$"  = "$"
        }
        Next  = "NotifySecurityTeam"
        Catch = [{ ErrorEquals = ["States.ALL"], Next = "NotifySecurityTeam" }]
      }
      NotifySecurityTeam = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn   = aws_sns_topic.security.arn
          "Message.$" = "States.JsonToString($)"
          Subject    = "CRITICAL: EC2 Incident Response Triggered"
        }
        Next = "WaitForApproval"
      }
      WaitForApproval = {
        Type    = "Task"
        Resource = "arn:aws:states:::lambda:invoke.waitForTaskToken"
        Parameters = {
          FunctionName = "${var.name}-ir-approval-gate"
          Payload = {
            "taskToken.$" = "$$.Task.Token"
            "context.$"   = "$"
          }
        }
        TimeoutSeconds = 86400
        Next           = "TerminateInstance"
        Catch = [{ ErrorEquals = ["States.TaskFailed"], Next = "IRComplete" }]
      }
      TerminateInstance = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = "${var.name}-terminate-ec2"
          "Payload.$"  = "$"
        }
        Next = "IRComplete"
      }
      IRComplete = {
        Type = "Succeed"
      }
    }
  })

  tags = { Name = "${var.name}-ec2-ir", Compliance = "NIST-800-61" }
}

resource "aws_iam_role" "sfn_ir" {
  name = "${var.name}-sfn-ir-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "states.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "sfn_ir" {
  name = "${var.name}-sfn-ir-policy"
  role = aws_iam_role.sfn_ir.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = "arn:aws:lambda:${var.aws_region}:*:function:${var.name}-*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.security.arn]
      }
    ]
  })
}
