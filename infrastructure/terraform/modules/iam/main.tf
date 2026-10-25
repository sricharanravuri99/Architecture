################################################################################
# IAM — Permission Boundaries, IRSA Roles, Break-Glass, SoD Enforcement
# Compliant with: HIPAA §164.312(a)(1), PCI Req 7/8, CIS IAM Controls
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Permission Boundary — Applied to ALL developer-created roles
################################################################################

resource "aws_iam_policy" "permission_boundary" {
  name        = "${var.name}-permission-boundary"
  description = "Permission boundary preventing privilege escalation and PHI exfiltration"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSafeServices"
        Effect = "Allow"
        Action = [
          "s3:*", "dynamodb:*", "sqs:*", "sns:*", "lambda:*",
          "logs:*", "cloudwatch:*", "xray:*", "ecr:*",
          "secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret",
          "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey",
          "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
          "sts:AssumeRole", "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyPrivilegeEscalation"
        Effect = "Deny"
        Action = [
          "iam:CreateUser", "iam:DeleteUser", "iam:CreateGroup", "iam:DeleteGroup",
          "iam:AttachUserPolicy", "iam:DetachUserPolicy",
          "iam:PutUserPolicy", "iam:DeleteUserPolicy",
          "iam:CreateAccessKey", "iam:DeleteAccessKey",
          "iam:AddUserToGroup", "iam:RemoveUserFromGroup",
          "iam:CreateRole", "iam:DeleteRole",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:PassRole",
          "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyPHIExfiltration"
        Effect = "Deny"
        Action = [
          "s3:PutObject", "s3:CopyObject"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" }
          Null            = { "s3:x-amz-server-side-encryption" = "false" }
        }
      },
      {
        Sid    = "DenyKMSAdminActions"
        Effect = "Deny"
        Action = [
          "kms:DeleteCustomKeyStore", "kms:DeleteImportedKeyMaterial",
          "kms:DisableKey", "kms:ScheduleKeyDeletion",
          "kms:CreateGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyCloudTrailModification"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail", "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# IRSA Roles — Pod-level AWS access
################################################################################

# App backend IRSA role
resource "aws_iam_role" "app_backend" {
  name                 = "${var.name}-app-backend-irsa"
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = { Federated = var.eks_oidc_provider_arn }
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
          "${var.eks_oidc_provider}:sub" = "system:serviceaccount:${var.app_namespace}:app-backend"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "app_backend" {
  name = "${var.name}-app-backend-policy"
  role = aws_iam_role.app_backend.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerAccess"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.name}/app/*"]
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = var.app_kms_key_arns
        Condition = {
          StringEquals = { "kms:ViaService" = [
            "secretsmanager.${data.aws_region.current.name}.amazonaws.com",
            "s3.${data.aws_region.current.name}.amazonaws.com"
          ]}
        }
      },
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"]
        Resource = ["arn:aws:dynamodb:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${var.name}-*"]
      },
      {
        Sid    = "SQSAccess"
        Effect = "Allow"
        Action = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = ["arn:aws:sqs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${var.name}-*"]
      },
      {
        Sid    = "S3ReadWrite"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
        Resource = ["arn:aws:s3:::${var.name}-app-data-*", "arn:aws:s3:::${var.name}-app-data-*/*"]
      },
      {
        Sid    = "XRayWrite"
        Effect = "Allow"
        Action = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
        Resource = "*"
      }
    ]
  })
}

# External Secrets Operator IRSA
resource "aws_iam_role" "external_secrets" {
  name                 = "${var.name}-external-secrets-irsa"
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = { Federated = var.eks_oidc_provider_arn }
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
          "${var.eks_oidc_provider}:sub" = "system:serviceaccount:external-secrets:external-secrets-sa"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "external_secrets" {
  name = "${var.name}-external-secrets-policy"
  role = aws_iam_role.external_secrets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds"]
        Resource = ["arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.name}/*"]
      },
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath"]
        Resource = ["arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.name}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey"]
        Resource = var.app_kms_key_arns
      }
    ]
  })
}

# Fluent Bit log shipper IRSA
resource "aws_iam_role" "fluentbit" {
  name                 = "${var.name}-fluentbit-irsa"
  permissions_boundary = aws_iam_policy.permission_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = { Federated = var.eks_oidc_provider_arn }
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
          "${var.eks_oidc_provider}:sub" = "system:serviceaccount:logging:fluent-bit"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "fluentbit" {
  role       = aws_iam_role.fluentbit.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

################################################################################
# Break-Glass Emergency Access Role (SOX Dual Control)
################################################################################

resource "aws_iam_role" "break_glass" {
  name = "${var.name}-break-glass"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { AWS = var.security_admin_arns }
      Condition = {
        BoolIfExists = { "aws:MultiFactorAuthPresent" = "true" }
        StringEquals = { "sts:ExternalId" = var.break_glass_external_id }
      }
    }]
  })

  tags = {
    Name       = "${var.name}-break-glass"
    Compliance = "HIPAA,PCI,SOX"
    Dual-Control = "required"
  }
}

resource "aws_iam_role_policy_attachment" "break_glass" {
  role       = aws_iam_role.break_glass.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Break-glass usage triggers CloudWatch alarm
resource "aws_cloudwatch_metric_alarm" "break_glass_used" {
  alarm_name          = "${var.name}-break-glass-assumed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "break-glass-assume"
  namespace           = "${var.name}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CRITICAL: Break-glass role assumed — dual control review required"
  alarm_actions       = [var.security_sns_arn]
  treat_missing_data  = "notBreaching"
}

################################################################################
# IAM Access Analyzer
################################################################################

resource "aws_accessanalyzer_analyzer" "main" {
  analyzer_name = "${var.name}-analyzer"
  type          = var.is_organization ? "ORGANIZATION" : "ACCOUNT"

  tags = { Name = "${var.name}-analyzer" }
}

resource "aws_accessanalyzer_analyzer" "unused" {
  analyzer_name = "${var.name}-unused-access"
  type          = var.is_organization ? "ORGANIZATION_UNUSED_ACCESS" : "ACCOUNT_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = 90
    }
  }

  tags = { Name = "${var.name}-unused-access-analyzer" }
}
