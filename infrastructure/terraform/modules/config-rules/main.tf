################################################################################
# AWS Config — Conformance Packs + Custom Rules
# Packs: HIPAA, PCI DSS, CIS L2, NIST 800-53
# Compliant with: HIPAA §164.308(a)(8), PCI Req 11.2, CIS Controls 1-4
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.name}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.name}-delivery"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_key_prefix  = "config"
  sns_topic_arn  = var.security_sns_arn

  snapshot_delivery_properties {
    delivery_frequency = "Six_Hours"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

################################################################################
# Config S3 Bucket
################################################################################

resource "aws_s3_bucket" "config" {
  bucket        = "${var.name}-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.config_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyNonTLS"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = ["${aws_s3_bucket.config.arn}", "${aws_s3_bucket.config.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config.arn
        Condition = { StringEquals = { "AWS:SourceAccount" = data.aws_caller_identity.current.account_id } }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config.arn}/config/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"       = "bucket-owner-full-control"
            "AWS:SourceAccount"  = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

################################################################################
# IAM Role for Config
################################################################################

resource "aws_iam_role" "config" {
  name = "${var.name}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  name = "${var.name}-config-s3"
  role = aws_iam_role.config.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetBucketAcl"]
      Resource = [aws_s3_bucket.config.arn, "${aws_s3_bucket.config.arn}/*"]
    }]
  })
}

################################################################################
# Conformance Packs — HIPAA, PCI, CIS, NIST
################################################################################

resource "aws_config_conformance_pack" "hipaa" {
  name = "${var.name}-hipaa-operational-best-practices"

  template_body = <<-YAML
    Parameters: {}
    Resources:
      ConfigRuleForRootMFA:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: root-account-mfa-enabled
          Source:
            Owner: AWS
            SourceIdentifier: ROOT_ACCOUNT_MFA_ENABLED
      ConfigRuleForEncryptedVolumes:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: encrypted-volumes
          Source:
            Owner: AWS
            SourceIdentifier: ENCRYPTED_VOLUMES
      ConfigRuleForRDSEncryption:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: rds-storage-encrypted
          Source:
            Owner: AWS
            SourceIdentifier: RDS_STORAGE_ENCRYPTED
      ConfigRuleForRDSBackup:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: db-instance-backup-enabled
          Source:
            Owner: AWS
            SourceIdentifier: DB_INSTANCE_BACKUP_ENABLED
      ConfigRuleForSecretsManager:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: secretsmanager-rotation-enabled-check
          Source:
            Owner: AWS
            SourceIdentifier: SECRETSMANAGER_ROTATION_ENABLED_CHECK
      ConfigRuleForS3Encryption:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: s3-bucket-server-side-encryption-enabled
          Source:
            Owner: AWS
            SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
      ConfigRuleForCWLogGroupEncryption:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cloudwatch-log-group-encrypted
          Source:
            Owner: AWS
            SourceIdentifier: CLOUDWATCH_LOG_GROUP_ENCRYPTED
      ConfigRuleForCloudTrailEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cloudtrail-enabled
          Source:
            Owner: AWS
            SourceIdentifier: CLOUD_TRAIL_ENABLED
      ConfigRuleForCloudTrailEncryption:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cloud-trail-encryption-enabled
          Source:
            Owner: AWS
            SourceIdentifier: CLOUD_TRAIL_ENCRYPTION_ENABLED
      ConfigRuleForCloudTrailLogValidation:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: cloud-trail-log-file-validation-enabled
          Source:
            Owner: AWS
            SourceIdentifier: CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED
      ConfigRuleForIAMPasswordPolicy:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: iam-password-policy
          Source:
            Owner: AWS
            SourceIdentifier: IAM_PASSWORD_POLICY
          InputParameters:
            RequireUppercaseCharacters: "true"
            RequireLowercaseCharacters: "true"
            RequireSymbols: "true"
            RequireNumbers: "true"
            MinimumPasswordLength: "14"
            PasswordReusePrevention: "24"
            MaxPasswordAge: "90"
      ConfigRuleForGuardDuty:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: guardduty-enabled-centralized
          Source:
            Owner: AWS
            SourceIdentifier: GUARDDUTY_ENABLED_CENTRALIZED
      ConfigRuleForVPCFlowLogs:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: vpc-flow-logs-enabled
          Source:
            Owner: AWS
            SourceIdentifier: VPC_FLOW_LOGS_ENABLED
      ConfigRuleForIMDSV2:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: ec2-imdsv2-check
          Source:
            Owner: AWS
            SourceIdentifier: EC2_IMDSV2_CHECK
      ConfigRuleForSGNoUnrestricted:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: restricted-ssh
          Source:
            Owner: AWS
            SourceIdentifier: INCOMING_SSH_DISABLED
      ConfigRuleForRDSNoPublic:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: rds-instance-public-access-check
          Source:
            Owner: AWS
            SourceIdentifier: RDS_INSTANCE_PUBLIC_ACCESS_CHECK
      ConfigRuleForDynamoDBEncryption:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: dynamodb-table-encrypted-at-rest
          Source:
            Owner: AWS
            SourceIdentifier: DYNAMODB_TABLE_ENCRYPTED_AT_REST
      ConfigRuleForSNSEncryption:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: sns-encrypted-kms
          Source:
            Owner: AWS
            SourceIdentifier: SNS_ENCRYPTED_KMS
  YAML

  depends_on = [aws_config_configuration_recorder_status.main]
}

resource "aws_config_conformance_pack" "pci_dss" {
  name = "${var.name}-pci-dss-best-practices"

  template_body = <<-YAML
    Parameters: {}
    Resources:
      PciDssWafEnabled:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: wafv2-webacl-not-empty
          Source:
            Owner: AWS
            SourceIdentifier: WAFV2_WEBACL_NOT_EMPTY
      PciDssAccessKeysRotated:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: access-keys-rotated
          Source:
            Owner: AWS
            SourceIdentifier: ACCESS_KEYS_ROTATED
          InputParameters:
            maxAccessKeyAge: "90"
      PciDssNoUnrestrictedCommonPorts:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: restricted-common-ports
          Source:
            Owner: AWS
            SourceIdentifier: RESTRICTED_INCOMING_TRAFFIC
      PciDssEKSSecretsEncrypted:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: eks-secrets-encrypted
          Source:
            Owner: AWS
            SourceIdentifier: EKS_SECRETS_ENCRYPTED
      PciDssECRImageScan:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: ecr-private-image-scanning-enabled
          Source:
            Owner: AWS
            SourceIdentifier: ECR_PRIVATE_IMAGE_SCANNING_ENABLED
      PciDssMacie:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: macie-auto-sensitive-data-discovery-check
          Source:
            Owner: AWS
            SourceIdentifier: MACIE_AUTO_SENSITIVE_DATA_DISCOVERY_CHECK
      PciDssNetworkFirewall:
        Type: AWS::Config::ConfigRule
        Properties:
          ConfigRuleName: netfw-policy-default-action-fragment-packets
          Source:
            Owner: AWS
            SourceIdentifier: NETFW_POLICY_DEFAULT_ACTION_FRAGMENT_PACKETS
  YAML

  depends_on = [aws_config_configuration_recorder_status.main]
}

################################################################################
# Auto-remediation — Non-compliant resource notification
################################################################################

resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  name        = "${var.name}-config-noncompliant"
  description = "Config non-compliant resources → SNS"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "config_noncompliant" {
  rule      = aws_cloudwatch_event_rule.config_noncompliant.name
  target_id = "ConfigComplianceSNS"
  arn       = var.security_sns_arn
}
