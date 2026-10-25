################################################################################
# Monitoring — AMP, AMG, CloudWatch, Alarms, Dashboards
# Compliant with: HIPAA §164.308(a)(6)(ii), PCI Req 10.6, CIS Monitoring
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Amazon Managed Prometheus (AMP)
################################################################################

resource "aws_prometheus_workspace" "main" {
  alias = "${var.name}-prometheus"

  logging_configuration {
    log_group_arn = "${aws_cloudwatch_log_group.amp.arn}:*"
  }

  tags = { Name = "${var.name}-prometheus" }
}

resource "aws_cloudwatch_log_group" "amp" {
  name              = "/aws/prometheus/${var.name}"
  retention_in_days = 400
  kms_key_id        = var.kms_key_arn
}

# IRSA role for ADOT Collector → AMP
resource "aws_iam_role" "adot" {
  name = "${var.name}-adot-collector-irsa"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = { Federated = var.eks_oidc_provider_arn }
      Condition = {
        StringEquals = {
          "${var.eks_oidc_provider}:aud" = "sts.amazonaws.com"
          "${var.eks_oidc_provider}:sub" = "system:serviceaccount:monitoring:adot-collector"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "adot" {
  name = "${var.name}-adot-policy"
  role = aws_iam_role.adot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "aps:RemoteWrite", "aps:GetSeries", "aps:GetLabels",
          "aps:GetMetricMetadata", "aps:QueryMetrics"
        ]
        Resource = aws_prometheus_workspace.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments", "xray:PutTelemetryRecords",
          "xray:GetSamplingRules", "xray:GetSamplingTargets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup", "logs:CreateLogStream",
          "logs:PutLogEvents", "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

################################################################################
# Amazon Managed Grafana (AMG)
################################################################################

resource "aws_grafana_workspace" "main" {
  name                     = "${var.name}-grafana"
  account_access_type      = "CURRENT_ACCOUNT"
  authentication_providers = ["SAML", "AWS_SSO"]
  permission_type          = "SERVICE_MANAGED"
  data_sources             = ["PROMETHEUS", "CLOUDWATCH", "XRAY", "TIMESTREAM"]
  notification_destinations = ["SNS"]

  vpc_configuration {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.grafana_sg_id]
  }

  role_arn = aws_iam_role.grafana.arn

  tags = { Name = "${var.name}-grafana" }
}

resource "aws_iam_role" "grafana" {
  name = "${var.name}-grafana-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "grafana.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "grafana_prometheus" {
  role       = aws_iam_role.grafana.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonPrometheusQueryAccess"
}

resource "aws_iam_role_policy_attachment" "grafana_cloudwatch" {
  role       = aws_iam_role.grafana.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess"
}

################################################################################
# CloudWatch Container Insights
################################################################################

resource "aws_cloudwatch_log_group" "eks_application" {
  name              = "/aws/eks/${var.cluster_name}/application"
  retention_in_days = 400
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "eks_performance" {
  name              = "/aws/eks/${var.cluster_name}/performance"
  retention_in_days = 90
  kms_key_id        = var.kms_key_arn
}

################################################################################
# Critical CloudWatch Alarms — Application + Infrastructure
################################################################################

locals {
  alarms = {
    # EKS
    eks_api_errors = {
      metric_name = "5xxCount"
      namespace   = "AWS/ApplicationELB"
      threshold   = 50
      desc        = "ALB 5xx errors > 50/5min"
    }
    # RDS
    rds_cpu_high = {
      metric_name = "CPUUtilization"
      namespace   = "AWS/RDS"
      threshold   = 90
      desc        = "RDS CPU > 90%"
    }
    rds_connections_high = {
      metric_name = "DatabaseConnections"
      namespace   = "AWS/RDS"
      threshold   = var.rds_max_connections * 0.8
      desc        = "RDS connections > 80% of max"
    }
    # ElastiCache
    redis_cpu_high = {
      metric_name = "EngineCPUUtilization"
      namespace   = "AWS/ElastiCache"
      threshold   = 80
      desc        = "Redis CPU > 80%"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "critical" {
  for_each            = local.alarms
  alarm_name          = "${var.name}-${each.key}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = each.value.metric_name
  namespace           = each.value.namespace
  period              = 300
  statistic           = "Average"
  threshold           = each.value.threshold
  alarm_description   = each.value.desc
  alarm_actions       = [var.alarm_sns_arn]
  ok_actions          = [var.alarm_sns_arn]
  treat_missing_data  = "notBreaching"
}

################################################################################
# SNS Topic for Alarms → PagerDuty
################################################################################

resource "aws_sns_topic" "alarms" {
  name              = "${var.name}-alarms"
  kms_master_key_id = var.kms_key_arn

  tags = { Name = "${var.name}-alarms" }
}

resource "aws_sns_topic_subscription" "pagerduty" {
  count     = var.pagerduty_endpoint != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "https"
  endpoint  = var.pagerduty_endpoint

  delivery_policy = jsonencode({
    healthyRetryPolicy = {
      minDelayTarget     = 20
      maxDelayTarget     = 20
      numRetries         = 3
      numNoDelayRetries  = 0
      backoffFunction    = "linear"
    }
  })
}

################################################################################
# CloudWatch Synthetics — Availability Canaries
################################################################################

resource "aws_synthetics_canary" "health_check" {
  name                 = "${var.name}-health-canary"
  artifact_s3_location = "s3://${var.canary_bucket_name}/canary/"
  execution_role_arn   = aws_iam_role.canary.arn
  handler              = "pageLoadBlueprint.handler"
  runtime_version      = "syn-nodejs-puppeteer-7.0"
  start_canary         = true

  schedule {
    expression = "rate(5 minutes)"
  }

  run_config {
    timeout_in_seconds = 60
    memory_in_mb       = 960
    active_tracing     = true
  }

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [var.canary_sg_id]
  }

  tags = { Name = "${var.name}-health-canary" }
}

resource "aws_iam_role" "canary" {
  name = "${var.name}-canary-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "canary" {
  role       = aws_iam_role.canary.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "canary_s3" {
  name = "${var.name}-canary-s3"
  role = aws_iam_role.canary.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetBucketLocation"]
      Resource = ["arn:aws:s3:::${var.canary_bucket_name}/*", "arn:aws:s3:::${var.canary_bucket_name}"]
    }]
  })
}
