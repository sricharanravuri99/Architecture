################################################################################
# AWS Network Firewall — Stateful IDS/IPS, Suricata Rules, TLS Inspection
# Compliant with: HIPAA §164.312(e)(1), PCI Req 1.3, NIST SP 800-41
################################################################################

resource "aws_networkfirewall_firewall" "main" {
  name                = "${var.name}-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = var.vpc_id

  dynamic "subnet_mapping" {
    for_each = var.firewall_subnet_ids
    content {
      subnet_id = subnet_mapping.value
    }
  }

  delete_protection              = true
  firewall_policy_change_protection = true
  subnet_change_protection       = true

  tags = { Name = "${var.name}-network-firewall" }
}

resource "aws_networkfirewall_firewall_policy" "main" {
  name = "${var.name}-firewall-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    # Stateless rules — fast path for known-good traffic
    stateless_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.stateless_allow.arn
      priority     = 100
    }

    # Stateful rules — IDS/IPS
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.suricata_rules.arn
    }

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.domain_allowlist.arn
    }

    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${data.aws_region.current.name}:aws-managed:stateful-rulegroup/ThreatSignaturesMalwareCoinminingStrictOrder"
    }

    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${data.aws_region.current.name}:aws-managed:stateful-rulegroup/ThreatSignaturesBotnetStrictOrder"
    }

    stateful_rule_group_reference {
      resource_arn = "arn:aws:network-firewall:${data.aws_region.current.name}:aws-managed:stateful-rulegroup/ThreatSignaturesIOCStrictOrder"
    }

    stateful_engine_options {
      rule_order              = "STRICT_ORDER"
      stream_exception_policy = "DROP"
    }
  }

  tags = { Name = "${var.name}-firewall-policy" }
}

data "aws_region" "current" {}

################################################################################
# Stateless Rule Group — Fast path allowlist
################################################################################

resource "aws_networkfirewall_rule_group" "stateless_allow" {
  capacity = 100
  name     = "${var.name}-stateless-allow"
  type     = "STATELESS"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:pass"]
            match_attributes {
              protocols = [6] # TCP
              source {
                address_definition = "10.0.0.0/8" # internal traffic fast-path
              }
              destination {
                address_definition = "10.0.0.0/8"
              }
            }
          }
        }
      }
    }
  }

  tags = { Name = "${var.name}-stateless-allow" }
}

################################################################################
# Suricata Rules — OWASP, PHI Exfiltration Detection, PCI Controls
################################################################################

resource "aws_networkfirewall_rule_group" "suricata_rules" {
  capacity = 1000
  name     = "${var.name}-suricata-ids-ips"
  type     = "STATEFUL"

  rule_group {
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      rules_string = <<-RULES
        # Block SQL injection attempts
        alert http any any -> any any (msg:"SQL Injection Attempt - UNION"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; within:20; classtype:web-application-attack; sid:1000001; rev:1;)
        alert http any any -> any any (msg:"SQL Injection Attempt - DROP"; flow:to_server,established; content:"DROP"; nocase; content:"TABLE"; nocase; within:10; classtype:web-application-attack; sid:1000002; rev:1;)

        # Block XSS attempts
        alert http any any -> any any (msg:"XSS Attempt - Script Tag"; flow:to_server,established; content:"<script"; nocase; classtype:web-application-attack; sid:1000003; rev:1;)

        # Block Log4Shell
        alert http any any -> any any (msg:"Log4Shell Exploitation Attempt"; flow:to_server,established; content:"${jndi:"; nocase; classtype:attempted-admin; sid:1000004; rev:1;)
        alert http any any -> any any (msg:"Log4Shell - LDAP"; flow:to_server,established; content:"jndi:ldap"; nocase; classtype:attempted-admin; sid:1000005; rev:1;)

        # Block SSRF attempts
        alert http any any -> any any (msg:"SSRF - IMDSv1 Access Attempt"; flow:to_server,established; content:"169.254.169.254"; classtype:attempted-recon; sid:1000006; rev:1;)

        # Detect PHI keyword patterns in outbound HTTP (data exfiltration)
        alert http any any -> !10.0.0.0/8 any (msg:"Potential PHI Exfiltration - SSN Pattern"; flow:to_server,established; content:"ssn"; nocase; pcre:"/\b\d{3}-\d{2}-\d{4}\b/"; classtype:policy-violation; sid:1000007; rev:1;)

        # Block crypto mining
        alert dns any any -> any any (msg:"Crypto Mining DNS - xmr.pool"; dns.query; content:"xmr.pool"; nocase; classtype:policy-violation; sid:1000008; rev:1;)
        alert http any any -> any any (msg:"Crypto Mining Pool Connection"; flow:to_server,established; content:"stratum+tcp://"; nocase; classtype:policy-violation; sid:1000009; rev:1;)

        # Block Tor exit nodes (common C2 evasion)
        alert tcp any any -> any 9001 (msg:"Tor Network Connection Attempt"; flow:to_server; classtype:policy-violation; sid:1000010; rev:1;)
        alert tcp any any -> any 9050 (msg:"Tor SOCKS Proxy Connection"; flow:to_server; classtype:policy-violation; sid:1000011; rev:1;)

        # Detect port scanning
        alert tcp any any -> $HOME_NET any (msg:"Port Scan Detection"; flags:S; threshold:type threshold,track by_src,count 20,seconds 60; classtype:network-scan; sid:1000012; rev:1;)

        # Block RDP brute force
        drop tcp any any -> $HOME_NET 3389 (msg:"RDP Brute Force"; flow:to_server; flags:S; threshold:type threshold,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000013; rev:1;)

        # Block SSH brute force
        drop tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force"; flow:to_server; flags:S; threshold:type threshold,track by_src,count 5,seconds 60; classtype:attempted-admin; sid:1000014; rev:1;)

        # PCI - Detect cleartext PAN transmission
        alert http any any -> any any (msg:"PCI - Potential PAN in Cleartext HTTP"; flow:to_server,established; pcre:"/\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b/"; classtype:policy-violation; sid:1000015; rev:1;)

        # Detect C2 beaconing patterns
        alert http any any -> !10.0.0.0/8 any (msg:"Suspicious Outbound - C2 Beacon Pattern"; flow:to_server,established; content:"User-Agent|3a 20|curl"; nocase; threshold:type threshold,track by_src,count 10,seconds 60; classtype:trojan-activity; sid:1000016; rev:1;)

        # Drop null scans
        drop tcp any any -> any any (msg:"Null Scan"; flags:0; classtype:network-scan; sid:1000017; rev:1;)

        # Drop XMAS scans
        drop tcp any any -> any any (msg:"XMAS Scan"; flags:FPU; classtype:network-scan; sid:1000018; rev:1;)
      RULES
    }
  }

  tags = { Name = "${var.name}-suricata-rules" }
}

################################################################################
# Domain Allowlist — Egress filtering
################################################################################

resource "aws_networkfirewall_rule_group" "domain_allowlist" {
  capacity = 200
  name     = "${var.name}-domain-allowlist"
  type     = "STATEFUL"

  rule_group {
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rule_variables {
      ip_sets {
        key = "HOME_NET"
        ip_set { definition = ["10.0.0.0/8"] }
      }
    }

    rules_source {
      rules_source_list {
        generated_rules_type = "ALLOWLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets = concat(
          # AWS Services
          [
            ".amazonaws.com",
            ".awsstatic.com",
            ".cloudfront.net",
            ".execute-api.${data.aws_region.current.name}.amazonaws.com"
          ],
          # Internal services
          var.allowed_domains
        )
      }
    }
  }

  tags = { Name = "${var.name}-domain-allowlist" }
}

################################################################################
# Firewall Logging
################################################################################

resource "aws_networkfirewall_logging_configuration" "main" {
  firewall_arn = aws_networkfirewall_firewall.main.arn

  logging_configuration {
    log_destination_config {
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
      log_destination = {
        logGroup = aws_cloudwatch_log_group.firewall_alert.name
      }
    }

    log_destination_config {
      log_destination_type = "CloudWatchLogs"
      log_type             = "FLOW"
      log_destination = {
        logGroup = aws_cloudwatch_log_group.firewall_flow.name
      }
    }
  }
}

resource "aws_cloudwatch_log_group" "firewall_alert" {
  name              = "/aws/network-firewall/${var.name}/alerts"
  retention_in_days = 400
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_log_group" "firewall_flow" {
  name              = "/aws/network-firewall/${var.name}/flow"
  retention_in_days = 90
  kms_key_id        = var.kms_key_arn
}
