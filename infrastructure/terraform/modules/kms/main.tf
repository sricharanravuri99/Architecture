################################################################################
# KMS Key Hierarchy — Data Classification Tiers
# Tier 1 (RESTRICTED): PHI / PAN  → CloudHSM-backed custom key store
# Tier 2 (CONFIDENTIAL): Internal → Standard CMK
# Tier 3 (GENERAL): Infra logs   → Standard CMK
# Compliant with: HIPAA §164.312(a)(2)(iv), PCI-DSS Req 3.5/3.7
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
}

# PHI Key — for Protected Health Information (HIPAA)
resource "aws_kms_key" "phi" {
  description              = "${var.name} PHI encryption key — HIPAA in-scope"
  deletion_window_in_days  = 30
  enable_key_rotation      = true
  rotation_period_in_days  = 365
  multi_region             = true # Enable multi-region for DR
  custom_key_store_id      = var.cloudhsm_key_store_id != "" ? var.cloudhsm_key_store_id : null

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable root account administration"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow PHI service access"
        Effect = "Allow"
        Principal = { AWS = var.phi_role_arns }
        Action = [
          "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
          "kms:GenerateDataKey*", "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = [
              "s3.${local.region}.amazonaws.com",
              "rds.${local.region}.amazonaws.com",
              "healthlake.${local.region}.amazonaws.com",
              "secretsmanager.${local.region}.amazonaws.com"
            ]
          }
        }
      },
      {
        Sid    = "Deny use without MFA for key management"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action = ["kms:Delete*", "kms:Disable*", "kms:ScheduleKeyDeletion"]
        Resource = "*"
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
        }
      },
      {
        Sid    = "CloudTrail for PHI key usage"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name              = "${var.name}-phi-key"
    DataClassification = "RESTRICTED"
    Compliance        = "HIPAA"
    PHIKey            = "true"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${var.name}-phi"
  target_key_id = aws_kms_key.phi.key_id
}

# PAN Key — for Payment Card Industry data (PCI-DSS)
resource "aws_kms_key" "pan" {
  description             = "${var.name} PAN encryption key — PCI-DSS in-scope CDE"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 365
  multi_region            = true
  custom_key_store_id     = var.cloudhsm_key_store_id != "" ? var.cloudhsm_key_store_id : null

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable root account administration"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "CDE services only"
        Effect = "Allow"
        Principal = { AWS = var.cde_role_arns }
        Action = [
          "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
          "kms:GenerateDataKey*", "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Deny non-CDE access"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action   = ["kms:Decrypt", "kms:Encrypt"]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = concat(var.cde_role_arns, ["arn:aws:iam::${local.account_id}:root"])
          }
        }
      }
    ]
  })

  tags = {
    Name               = "${var.name}-pan-key"
    DataClassification = "RESTRICTED"
    Compliance         = "PCI-DSS"
    CDEKey             = "true"
  }
}

resource "aws_kms_alias" "pan" {
  name          = "alias/${var.name}-pan"
  target_key_id = aws_kms_key.pan.key_id
}

# General application key — databases, S3, SQS, SNS
resource "aws_kms_key" "app" {
  description             = "${var.name} application encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 365
  multi_region            = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable root account"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow AWS services"
        Effect = "Allow"
        Principal = {
          Service = [
            "rds.amazonaws.com", "s3.amazonaws.com", "sqs.amazonaws.com",
            "sns.amazonaws.com", "logs.amazonaws.com", "backup.amazonaws.com",
            "elasticache.amazonaws.com", "es.amazonaws.com"
          ]
        }
        Action = ["kms:GenerateDataKey*", "kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name               = "${var.name}-app-key"
    DataClassification = "CONFIDENTIAL"
  }
}

resource "aws_kms_alias" "app" {
  name          = "alias/${var.name}-app"
  target_key_id = aws_kms_key.app.key_id
}

# Secrets Manager key
resource "aws_kms_key" "secrets" {
  description             = "${var.name} Secrets Manager encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  rotation_period_in_days = 90

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable root"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Secrets Manager service"
        Effect = "Allow"
        Principal = { Service = "secretsmanager.amazonaws.com" }
        Action = [
          "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
          "kms:GenerateDataKey*", "kms:DescribeKey", "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name               = "${var.name}-secrets-key"
    DataClassification = "CONFIDENTIAL"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${var.name}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# CloudTrail / audit log key (cannot be rotated while in use by CloudTrail)
resource "aws_kms_key" "cloudtrail" {
  description             = "${var.name} CloudTrail encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable root"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:GenerateDataKey*", "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals   = { "aws:SourceArn" = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.name}-org-trail" }
          StringLike     = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*" }
        }
      }
    ]
  })

  tags = {
    Name               = "${var.name}-cloudtrail-key"
    DataClassification = "CONFIDENTIAL"
    Compliance         = "HIPAA,PCI-DSS,SOX"
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.name}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# EKS secrets encryption key
resource "aws_kms_key" "eks" {
  description             = "${var.name} EKS secrets envelope encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "Enable root"
      Effect = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action   = "kms:*"
      Resource = "*"
    }]
  })

  tags = { Name = "${var.name}-eks-key" }
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${var.name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

# Terraform state encryption key
resource "aws_kms_key" "tfstate" {
  description             = "${var.name} Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = { Name = "${var.name}-tfstate-key" }
}

resource "aws_kms_alias" "tfstate" {
  name          = "alias/${var.name}-tfstate-key"
  target_key_id = aws_kms_key.tfstate.key_id
}
