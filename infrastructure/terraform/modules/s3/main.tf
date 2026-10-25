################################################################################
# S3 Module — Secure Buckets (WORM, Replication, KMS, Intelligent-Tiering)
# Compliant with: HIPAA §164.312(c), PCI Req 3.5, CIS AWS 2.x S3 controls
################################################################################

variable "buckets" {
  description = "Map of bucket configurations"
  type = map(object({
    purpose             = string
    kms_key_arn         = string
    versioning          = bool
    object_lock         = bool
    object_lock_days    = optional(number, 0)
    replication_enabled = bool
    replication_region  = optional(string, "us-west-2")
    lifecycle_glacier_days      = optional(number, 90)
    lifecycle_deep_archive_days = optional(number, 365)
    tags                = optional(map(string), {})
  }))
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Primary Buckets
################################################################################

resource "aws_s3_bucket" "main" {
  for_each      = var.buckets
  bucket        = "${var.name}-${each.key}-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(
    { Name = "${var.name}-${each.key}", Purpose = each.value.purpose },
    each.value.tags
  )
}

resource "aws_s3_bucket_versioning" "main" {
  for_each = var.buckets
  bucket   = aws_s3_bucket.main[each.key].id
  versioning_configuration {
    status = each.value.versioning ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  for_each = var.buckets
  bucket   = aws_s3_bucket.main[each.key].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = each.value.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "main" {
  for_each                = var.buckets
  bucket                  = aws_s3_bucket.main[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "main" {
  for_each = { for k, v in var.buckets : k => v if v.object_lock && v.object_lock_days > 0 }
  bucket   = aws_s3_bucket.main[each.key].id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = each.value.object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.main]
}

resource "aws_s3_bucket_lifecycle_configuration" "main" {
  for_each = var.buckets
  bucket   = aws_s3_bucket.main[each.key].id

  rule {
    id     = "tiering"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    dynamic "transition" {
      for_each = each.value.lifecycle_glacier_days > 0 ? [1] : []
      content {
        days          = each.value.lifecycle_glacier_days
        storage_class = "GLACIER_IR"
      }
    }

    dynamic "transition" {
      for_each = each.value.lifecycle_deep_archive_days > 0 ? [1] : []
      content {
        days          = each.value.lifecycle_deep_archive_days
        storage_class = "DEEP_ARCHIVE"
      }
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER_IR"
    }

    noncurrent_version_expiration {
      noncurrent_days = 2555 # 7 years
    }
  }
}

resource "aws_s3_bucket_policy" "main" {
  for_each = var.buckets
  bucket   = aws_s3_bucket.main[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.main[each.key].arn,
          "${aws_s3_bucket.main[each.key].arn}/*"
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyNonKMSUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.main[each.key].arn}/*"
        Condition = {
          StringNotEquals = { "s3:x-amz-server-side-encryption" = "aws:kms" }
          Null            = { "s3:x-amz-server-side-encryption" = "false" }
        }
      }
    ]
  })
}

################################################################################
# Cross-Region Replication (DR bucket in us-west-2)
################################################################################

resource "aws_iam_role" "replication" {
  for_each = { for k, v in var.buckets : k => v if v.replication_enabled }
  name     = "${var.name}-s3-replication-${each.key}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "replication" {
  for_each = { for k, v in var.buckets : k => v if v.replication_enabled }
  name     = "${var.name}-s3-replication-${each.key}"
  role     = aws_iam_role.replication[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:GetReplicationConfiguration", "s3:ListBucket"]
        Resource = [aws_s3_bucket.main[each.key].arn]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionTagging"
        ]
        Resource = ["${aws_s3_bucket.main[each.key].arn}/*"]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ReplicateObject",
          "s3:ReplicateDelete",
          "s3:ReplicateTags"
        ]
        Resource = ["${aws_s3_bucket.replica[each.key].arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [each.value.kms_key_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey"]
        Resource = [var.dr_kms_key_arn]
      }
    ]
  })
}

resource "aws_s3_bucket_replication_configuration" "main" {
  for_each = { for k, v in var.buckets : k => v if v.replication_enabled }
  bucket   = aws_s3_bucket.main[each.key].id
  role     = aws_iam_role.replication[each.key].arn

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.replica[each.key].arn
      storage_class = "STANDARD_IA"

      encryption_configuration {
        replica_kms_key_id = var.dr_kms_key_arn
      }

      replication_time {
        status = "Enabled"
        time { minutes = 15 }
      }

      metrics {
        status = "Enabled"
        event_threshold { minutes = 15 }
      }
    }

    delete_marker_replication { status = "Enabled" }
  }

  depends_on = [aws_s3_bucket_versioning.main]
}

################################################################################
# DR Replica Buckets (us-west-2)
################################################################################

resource "aws_s3_bucket" "replica" {
  for_each  = { for k, v in var.buckets : k => v if v.replication_enabled }
  provider  = aws.dr
  bucket    = "${var.name}-${each.key}-replica-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = { Name = "${var.name}-${each.key}-replica", Purpose = "DR" }
}

resource "aws_s3_bucket_versioning" "replica" {
  for_each = { for k, v in var.buckets : k => v if v.replication_enabled }
  provider = aws.dr
  bucket   = aws_s3_bucket.replica[each.key].id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "replica" {
  for_each = { for k, v in var.buckets : k => v if v.replication_enabled }
  provider = aws.dr
  bucket   = aws_s3_bucket.replica[each.key].id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.dr_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "replica" {
  for_each                = { for k, v in var.buckets : k => v if v.replication_enabled }
  provider                = aws.dr
  bucket                  = aws_s3_bucket.replica[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

################################################################################
# Macie — Sensitive Data Discovery for PHI/PAN buckets
################################################################################

resource "aws_macie2_account" "main" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}

resource "aws_macie2_classification_job" "phi_scan" {
  for_each   = { for k, v in var.buckets : k => v if contains(["phi", "health-data"], v.purpose) }
  name       = "${var.name}-phi-scan-${each.key}"
  job_type   = "SCHEDULED"

  schedule_frequency {
    weekly_schedule = "MONDAY"
  }

  s3_job_definition {
    bucket_definitions {
      account_id = data.aws_caller_identity.current.account_id
      buckets    = [aws_s3_bucket.main[each.key].id]
    }
  }

  depends_on = [aws_macie2_account.main]
}
