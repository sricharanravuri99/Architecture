################################################################################
# Security Hub — All Standards + Custom Insights
# Standards: CIS AWS 2.0, PCI DSS v3.2.1, NIST SP 800-53, AWS FSBP
# Compliant with: HIPAA §164.308(a)(1), PCI Req 11, CIS Controls v8
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_securityhub_account" "main" {
  enable_default_standards                = false
  auto_enable_controls                    = true
  control_finding_generator               = "SECURITY_CONTROL"
}

################################################################################
# Compliance Standards
################################################################################

resource "aws_securityhub_standards_subscription" "cis_v2" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/2.0.0"
}

resource "aws_securityhub_standards_subscription" "pci_dss" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/nist-800-53/v/5.0.0"
}

resource "aws_securityhub_standards_subscription" "aws_fsbp" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

################################################################################
# Custom Insights
################################################################################

resource "aws_securityhub_insight" "critical_unresolved" {
  name = "${var.name}-critical-unresolved"

  filters {
    severity_label {
      comparison = "EQUALS"
      value      = "CRITICAL"
    }
    workflow_status {
      comparison = "NOT_EQUALS"
      value      = "RESOLVED"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "ResourceType"
}

resource "aws_securityhub_insight" "phi_related_findings" {
  name = "${var.name}-phi-data-risk"

  filters {
    resource_tags_key {
      comparison = "EQUALS"
      value      = "DataClassification"
    }
    resource_tags_value {
      comparison = "EQUALS"
      value      = "PHI"
    }
    severity_label {
      comparison = "EQUALS"
      value      = "HIGH"
    }
  }

  group_by_attribute = "ResourceType"
}

resource "aws_securityhub_insight" "pci_cde_findings" {
  name = "${var.name}-pci-cde-findings"

  filters {
    resource_tags_key {
      comparison = "EQUALS"
      value      = "PCIScope"
    }
    resource_tags_value {
      comparison = "EQUALS"
      value      = "CDE"
    }
    record_state {
      comparison = "EQUALS"
      value      = "ACTIVE"
    }
  }

  group_by_attribute = "GeneratorId"
}

################################################################################
# Security Hub → EventBridge → SNS (Critical Findings Notification)
################################################################################

resource "aws_cloudwatch_event_rule" "securityhub_critical" {
  name        = "${var.name}-securityhub-critical"
  description = "Security Hub CRITICAL findings → immediate notification"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["CRITICAL", "HIGH"]
        }
        RecordState = ["ACTIVE"]
        WorkflowState = ["NEW"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_sns" {
  rule      = aws_cloudwatch_event_rule.securityhub_critical.name
  target_id = "SecurityHubSNS"
  arn       = var.security_sns_arn
}

################################################################################
# Member accounts (for Organizations integration)
################################################################################

resource "aws_securityhub_organization_configuration" "main" {
  count       = var.is_delegated_admin ? 1 : 0
  auto_enable = true
  auto_enable_standards = "NONE"

  organization_configuration {
    configuration_type = "CENTRAL"
  }
}
