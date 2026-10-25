################################################################################
# WAF v2 — Comprehensive Rule Set
# OWASP Top 10 · Bot Control · IP Reputation · Rate Limiting · Geo-blocking
# Compliant with: PCI-DSS Req 6.4, HIPAA §164.312
################################################################################

resource "aws_wafv2_ip_set" "blocked" {
  name               = "${var.name}-blocked-ips"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.blocked_ip_list
  description        = "Manually blocked IP addresses"
  tags               = { Name = "${var.name}-blocked-ips" }
}

resource "aws_wafv2_ip_set" "allowed" {
  name               = "${var.name}-allowed-ips"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = var.allowed_ip_list
  description        = "Trusted IP addresses (office, VPN egress)"
  tags               = { Name = "${var.name}-allowed-ips" }
}

resource "aws_wafv2_web_acl" "main" {
  name        = "${var.name}-waf"
  scope       = var.scope
  description = "Main WAF ACL — OWASP + Bot Control + IP Reputation + Rate Limiting"

  default_action { allow {} }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-waf"
    sampled_requests_enabled   = true
  }

  # Rule 1: Block known bad IPs (manual blocklist)
  rule {
    name     = "BlockedIPsRule"
    priority = 1
    action { block {} }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockedIPsRule"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: AWS IP Reputation list (known malicious IPs)
  rule {
    name     = "AWSManagedIPReputationList"
    priority = 2
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSIPReputationList"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: Anonymous IP list (TOR, VPN, hosting)
  rule {
    name     = "AWSManagedAnonymousIPList"
    priority = 3
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
        rule_action_override {
          name          = "HostingProviderIPList"
          action_to_use { count {} } # Count only, don't block hosting providers
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AnonymousIPList"
      sampled_requests_enabled   = true
    }
  }

  # Rule 4: Core rule set (OWASP Top 10)
  rule {
    name     = "AWSManagedCoreRuleSet"
    priority = 4
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
        rule_action_override {
          name          = "SizeRestrictions_BODY"
          action_to_use { count {} }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CRSRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 5: Known bad inputs (Log4Shell, SSRF, etc.)
  rule {
    name     = "AWSManagedKnownBadInputs"
    priority = 5
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  # Rule 6: SQL injection
  rule {
    name     = "AWSManagedSQLiRuleSet"
    priority = 6
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "SQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 7: Linux OS protection
  rule {
    name     = "AWSManagedLinuxRuleSet"
    priority = 7
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesLinuxRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "LinuxRuleSet"
      sampled_requests_enabled   = true
    }
  }

  # Rule 8: Rate limiting — per IP (DDoS / brute force protection)
  rule {
    name     = "RateLimitPerIP"
    priority = 8
    action { block {} }
    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_5min
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  # Rule 9: API rate limiting — stricter for auth endpoints
  rule {
    name     = "RateLimitAuthEndpoints"
    priority = 9
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 100 # 100 auth requests per 5 min per IP
        aggregate_key_type = "IP"
        scope_down_statement {
          byte_match_statement {
            search_string         = "/auth/"
            field_to_match        { uri_path {} }
            text_transformation { priority = 0; type = "LOWERCASE" }
            positional_constraint = "CONTAINS"
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AuthRateLimit"
      sampled_requests_enabled   = true
    }
  }

  # Rule 10: Block non-allowed geo locations (customize per business requirement)
  dynamic "rule" {
    for_each = length(var.allowed_countries) > 0 ? [1] : []
    content {
      name     = "GeoBlockNonAllowed"
      priority = 10
      action { block {} }
      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = var.allowed_countries
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "GeoBlock"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 11: Bot Control (managed)
  dynamic "rule" {
    for_each = var.enable_bot_control ? [1] : []
    content {
      name     = "AWSManagedBotControl"
      priority = 11
      override_action { none {} }
      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesBotControlRuleSet"
          vendor_name = "AWS"
          managed_rule_group_configs {
            aws_managed_rules_bot_control_rule_set {
              inspection_level = "TARGETED"
            }
          }
          rule_action_override {
            name          = "CategoryVerifiedSearchEngine"
            action_to_use { allow {} }
          }
          rule_action_override {
            name          = "CategoryVerifiedSocialMedia"
            action_to_use { allow {} }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "BotControl"
        sampled_requests_enabled   = true
      }
    }
  }

  tags = { Name = "${var.name}-waf" }
}

################################################################################
# WAF Logging — All traffic logged to Kinesis/S3
################################################################################
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  log_destination_configs = [var.log_destination_arn]
  resource_arn            = aws_wafv2_web_acl.main.arn

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior    = "DROP"
      requirement = "MEETS_ALL"
      condition {
        action_condition { action = "ALLOW" }
      }
      condition {
        label_name_condition { label_name = "awswaf:managed:aws:bot-control:verified" }
      }
    }
  }
}

# Associate WAF with CloudFront (done at CloudFront level) or ALB
resource "aws_wafv2_web_acl_association" "alb" {
  count        = var.scope == "REGIONAL" && var.alb_arn != "" ? 1 : 0
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# Associate WAF with API Gateway
resource "aws_wafv2_web_acl_association" "api_gateway" {
  count        = var.scope == "REGIONAL" && var.api_gateway_arn != "" ? 1 : 0
  resource_arn = var.api_gateway_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
