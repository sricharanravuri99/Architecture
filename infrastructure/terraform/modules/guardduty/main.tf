################################################################################
# GuardDuty — All Features Enabled (EKS, S3, Malware, RDS, Lambda)
# Auto-remediation via EventBridge → Step Functions
# Compliant with: CIS AWS 2.x, HIPAA §164.308(a)(6), PCI Req 11
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  datasources {
    s3_logs { enable = true }
    kubernetes {
      audit_logs { enable = true }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes { enable = true }
      }
    }
  }

  tags = { Name = "${var.name}-guardduty" }
}

# EKS Runtime Monitoring (eBPF-based)
resource "aws_guardduty_detector_feature" "eks_runtime" {
  detector_id = aws_guardduty_detector.main.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
}

# RDS Login Events protection
resource "aws_guardduty_detector_feature" "rds_login" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# Lambda Network Activity monitoring
resource "aws_guardduty_detector_feature" "lambda" {
  detector_id = aws_guardduty_detector.main.id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

# Runtime monitoring for ECS
resource "aws_guardduty_detector_feature" "ecs_runtime" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "ENABLED"
  }
}

################################################################################
# GuardDuty Finding → EventBridge → Step Functions IR Playbook
################################################################################

# CloudWatch Event rule for HIGH/CRITICAL GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.name}-guardduty-high-critical"
  description = "GuardDuty HIGH and CRITICAL findings → auto-remediation"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [
        { numeric = [">=", 7] }  # HIGH (7+) and CRITICAL (9+)
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "SecurityTeamSNS"
  arn       = var.security_sns_arn

  input_transformer {
    input_paths = {
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      account     = "$.detail.accountId"
      region      = "$.region"
      resource    = "$.detail.resource.resourceType"
      description = "$.detail.description"
      finding_id  = "$.detail.id"
    }
    input_template = <<-EOT
    {
      "alert": "GuardDuty Finding",
      "severity": "<severity>",
      "type": "<type>",
      "account": "<account>",
      "region": "<region>",
      "resource": "<resource>",
      "description": "<description>",
      "finding_id": "<finding_id>",
      "console_url": "https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?macros=current&fId=<finding_id>"
    }
    EOT
  }
}

# Step Functions IR workflow trigger (for EC2 compromise)
resource "aws_cloudwatch_event_target" "guardduty_step_functions" {
  count     = var.ir_step_function_arn != "" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "IRStepFunction"
  arn       = var.ir_step_function_arn
  role_arn  = aws_iam_role.eventbridge_sfn.arn
}

resource "aws_iam_role" "eventbridge_sfn" {
  name = "${var.name}-eventbridge-sfn-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "events.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_sfn" {
  name = "${var.name}-eventbridge-sfn-policy"
  role = aws_iam_role.eventbridge_sfn.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["states:StartExecution"]
      Resource = [var.ir_step_function_arn]
    }]
  })
}

# Separate rules for specific finding types
resource "aws_cloudwatch_event_rule" "compromised_credentials" {
  name = "${var.name}-compromised-credentials"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "UnauthorizedAccess:IAMUser" }, { prefix = "CredentialAccess:IAMUser" }]
    }
  })
}

resource "aws_cloudwatch_event_target" "compromised_credentials" {
  rule      = aws_cloudwatch_event_rule.compromised_credentials.name
  target_id = "SecuritySNS"
  arn       = var.security_sns_arn
}

################################################################################
# Threat intelligence feeds (custom)
################################################################################
resource "aws_guardduty_threatintelset" "custom" {
  count       = var.custom_threat_intel_s3_uri != "" ? 1 : 0
  activate    = true
  detector_id = aws_guardduty_detector.main.id
  format      = "TXT"
  location    = var.custom_threat_intel_s3_uri
  name        = "${var.name}-custom-threatintel"
  tags        = { Name = "${var.name}-custom-threatintel" }
}
