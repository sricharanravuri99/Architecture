################################################################################
# AWS Backup — 3-2-1-1 Rule, Vault Lock, Cross-Region, Cross-Account
# Compliant with: HIPAA §164.308(a)(7), PCI Req 9.8, CIS Backup Controls
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Backup Vaults
################################################################################

resource "aws_backup_vault" "primary" {
  name        = "${var.name}-backup-vault"
  kms_key_arn = var.kms_key_arn
  tags        = { Name = "${var.name}-backup-vault" }
}

resource "aws_backup_vault_lock_configuration" "primary" {
  backup_vault_name   = aws_backup_vault.primary.name
  min_retention_days  = 7
  max_retention_days  = 2555 # 7 years
  changeable_for_days = 3    # 3-day grace period before immutable
}

# DR vault (cross-region)
resource "aws_backup_vault" "dr" {
  provider    = aws.dr
  name        = "${var.name}-backup-vault-dr"
  kms_key_arn = var.dr_kms_key_arn
  tags        = { Name = "${var.name}-backup-vault-dr", Purpose = "DR" }
}

resource "aws_backup_vault_lock_configuration" "dr" {
  provider            = aws.dr
  backup_vault_name   = aws_backup_vault.dr.name
  min_retention_days  = 7
  max_retention_days  = 2555
  changeable_for_days = 3
}

################################################################################
# Backup Plans
################################################################################

resource "aws_backup_plan" "main" {
  name = "${var.name}-backup-plan"

  # Tier 1: Hourly — critical databases
  rule {
    rule_name         = "hourly-rds-elasticache"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 * * * ? *)" # every hour
    start_window      = 60
    completion_window = 120

    lifecycle {
      cold_storage_after = 30
      delete_after       = 90
    }

    recovery_point_tags = { Frequency = "hourly", Tier = "critical" }
  }

  # Tier 2: Daily — all resources
  rule {
    rule_name         = "daily-all-resources"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 2 * * ? *)" # 2 AM daily
    start_window      = 60
    completion_window = 480

    lifecycle {
      cold_storage_after = 30
      delete_after       = 365
    }

    # Copy to DR region
    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle {
        cold_storage_after = 30
        delete_after       = 365
      }
    }

    recovery_point_tags = { Frequency = "daily", Tier = "standard" }
  }

  # Tier 3: Weekly — long-term retention
  rule {
    rule_name         = "weekly-long-term"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 3 ? * SUN *)" # Sunday 3 AM
    start_window      = 60
    completion_window = 480

    lifecycle {
      cold_storage_after = 30
      delete_after       = 2555 # 7 years for compliance
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.dr.arn
      lifecycle {
        cold_storage_after = 30
        delete_after       = 2555
      }
    }

    recovery_point_tags = { Frequency = "weekly", Tier = "compliance" }
  }

  tags = { Name = "${var.name}-backup-plan" }
}

################################################################################
# Backup Selections — Tag-based
################################################################################

resource "aws_iam_role" "backup" {
  name = "${var.name}-backup-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "backup_restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_iam_role_policy_attachment" "backup_s3" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup"
}

# All resources tagged Backup=true
resource "aws_backup_selection" "tagged" {
  name         = "${var.name}-tagged-resources"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.main.id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}

# Explicit critical resources
resource "aws_backup_selection" "critical" {
  name         = "${var.name}-critical-resources"
  iam_role_arn = aws_iam_role.backup.arn
  plan_id      = aws_backup_plan.main.id

  resources = var.critical_resource_arns
}

################################################################################
# Backup Notifications
################################################################################

resource "aws_backup_vault_notifications" "main" {
  backup_vault_name   = aws_backup_vault.primary.name
  sns_topic_arn       = var.backup_sns_arn
  backup_vault_events = [
    "BACKUP_JOB_STARTED", "BACKUP_JOB_COMPLETED", "BACKUP_JOB_FAILED",
    "COPY_JOB_FAILED", "RESTORE_JOB_COMPLETED", "RESTORE_JOB_FAILED",
    "RECOVERY_POINT_MODIFIED"
  ]
}

################################################################################
# Backup Compliance Report
################################################################################

resource "aws_backup_report_plan" "compliance" {
  name        = "${var.name}-backup-compliance"
  description = "Daily backup compliance report — HIPAA/PCI"

  report_delivery_channel {
    s3_bucket_name = var.report_bucket_name
    s3_key_prefix  = "backup-reports/"
    formats        = ["CSV", "JSON"]
  }

  report_setting {
    report_template = "BACKUP_JOB_REPORT"
    regions         = [data.aws_region.current.name]
    accounts        = [data.aws_caller_identity.current.account_id]
  }
}
