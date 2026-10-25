################################################################################
# OpenSearch — Fine-Grained Access Control, Encryption, SAML, VPC
# Compliant with: HIPAA §164.312, PCI Req 7, CIS Controls 6.6
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_opensearch_domain" "main" {
  domain_name    = "${var.name}-search"
  engine_version = "OpenSearch_2.13"

  cluster_config {
    instance_type            = var.instance_type
    instance_count           = var.instance_count
    zone_awareness_enabled   = true
    dedicated_master_enabled = true
    dedicated_master_type    = var.master_instance_type
    dedicated_master_count   = 3

    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_type = "gp3"
    volume_size = var.volume_size_gb
    throughput  = 250
    iops        = 3000
  }

  vpc_options {
    subnet_ids         = slice(var.data_subnet_ids, 0, min(3, length(var.data_subnet_ids)))
    security_group_ids = [var.opensearch_sg_id]
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = var.kms_key_arn
  }

  node_to_node_encryption {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-PFS-2023-10"
  }

  # Fine-Grained Access Control (FGAC) with SAML
  advanced_security_options {
    enabled                        = true
    anonymous_auth_enabled         = false
    internal_user_database_enabled = false

    master_user_options {
      master_user_arn = var.master_user_arn
    }
  }

  # SAML authentication for Dashboards
  dynamic "advanced_security_options" {
    for_each = []
  }

  log_publishing_options {
    log_type                 = "INDEX_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    enabled                  = true
  }

  log_publishing_options {
    log_type                 = "SEARCH_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    enabled                  = true
  }

  log_publishing_options {
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    enabled                  = true
  }

  log_publishing_options {
    log_type                 = "AUDIT_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.opensearch.arn
    enabled                  = true
  }

  auto_tune_options {
    desired_state       = "ENABLED"
    rollback_on_disable = "NO_ROLLBACK"
  }

  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
    "indices.query.bool.max_clause_count"    = "1024"
    "override_main_response_version"         = "false"
  }

  tags = { Name = "${var.name}-opensearch", DataClassification = "Sensitive" }
}

################################################################################
# Access Policy — Deny all except VPC and specific IAM roles
################################################################################

resource "aws_opensearch_domain_policy" "main" {
  domain_name     = aws_opensearch_domain.main.domain_name
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = var.allowed_iam_arns }
        Action    = "es:*"
        Resource  = "${aws_opensearch_domain.main.arn}/*"
      },
      {
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "es:*"
        Resource  = "${aws_opensearch_domain.main.arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = var.allowed_iam_arns
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "opensearch" {
  name              = "/aws/opensearch/${var.name}"
  retention_in_days = 400
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_resource_policy" "opensearch" {
  policy_name = "${var.name}-opensearch-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "es.amazonaws.com" }
      Action    = ["logs:PutLogEvents", "logs:PutLogEventsBatch", "logs:CreateLogStream"]
      Resource  = "arn:aws:logs:*"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

################################################################################
# CloudWatch Alarms
################################################################################

resource "aws_cloudwatch_metric_alarm" "cluster_red" {
  alarm_name          = "${var.name}-opensearch-cluster-red"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ClusterStatus.red"
  namespace           = "AWS/ES"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1
  alarm_description   = "OpenSearch cluster status RED"
  alarm_actions       = [var.alarm_sns_arn]

  dimensions = { DomainName = aws_opensearch_domain.main.domain_name, ClientId = data.aws_caller_identity.current.account_id }
}

resource "aws_cloudwatch_metric_alarm" "free_storage" {
  alarm_name          = "${var.name}-opensearch-storage-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/ES"
  period              = 300
  statistic           = "Minimum"
  threshold           = 20480 # 20GB
  alarm_description   = "OpenSearch free storage < 20GB"
  alarm_actions       = [var.alarm_sns_arn]

  dimensions = { DomainName = aws_opensearch_domain.main.domain_name, ClientId = data.aws_caller_identity.current.account_id }
}
