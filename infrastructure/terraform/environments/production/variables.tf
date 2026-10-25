################################################################################
# Production Environment Variables
################################################################################

variable "name"         { type = string; default = "myapp-prod" }
variable "project_name" { type = string; default = "MyApp" }
variable "app_name"     { type = string; default = "MyApp" }
variable "aws_region"   { type = string; default = "us-east-1" }
variable "dr_region"    { type = string; default = "us-west-2" }
variable "owner"        { type = string }
variable "cost_center"  { type = string }

# Network
variable "vpc_cidr"                 { type = string; default = "10.0.0.0/16" }
variable "availability_zones"       { type = list(string) }
variable "public_subnet_cidrs"      { type = list(string) }
variable "management_subnet_cidrs"  { type = list(string) }
variable "private_subnet_cidrs"     { type = list(string) }
variable "data_subnet_cidrs"        { type = list(string) }
variable "cde_subnet_cidrs"         { type = list(string) }
variable "payment_processor_cidrs"  { type = list(string); default = [] }
variable "allowed_egress_domains"   { type = list(string); default = [] }
variable "allowed_countries"        { type = list(string); default = [] }

# EKS
variable "eks_cluster_version" { type = string; default = "1.30" }
variable "eks_cluster_admins"  { type = list(string) }
variable "app_namespace"       { type = string; default = "app" }

# Database
variable "database_name" { type = string; default = "appdb" }

# Auth
variable "redis_auth_token"         { type = string; sensitive = true }
variable "smart_fhir_callback_urls" { type = list(string) }
variable "smart_fhir_logout_urls"   { type = list(string) }

# DNS/TLS
variable "domain_name"             { type = string }
variable "domain_aliases"          { type = list(string) }
variable "route53_zone_id"         { type = string }
variable "alb_acm_cert_arn"        { type = string }
variable "cloudfront_acm_cert_arn" { type = string }
variable "cognito_acm_cert_arn"    { type = string; default = "" }

# CloudFront
variable "cloudfront_origin_secret" { type = string; sensitive = true }

# CloudHSM
variable "cloudhsm_key_store_password" { type = string; sensitive = true }
variable "cloudhsm_trust_anchor_cert"  { type = string }

# Security
variable "security_admin_arns"        { type = list(string) }
variable "break_glass_external_id"    { type = string; sensitive = true }
variable "cde_principal_arns"         { type = list(string); default = [] }
variable "security_team_email"        { type = string }
variable "custom_threat_intel_s3_uri" { type = string; default = "" }
variable "is_organization"            { type = bool; default = true }
variable "is_security_hub_delegated_admin" { type = bool; default = false }

# DR
variable "dr_kms_key_arn" { type = string; default = "" }

# Email/PagerDuty
variable "ses_from_email"    { type = string }
variable "ses_arn"           { type = string }
variable "pagerduty_endpoint" { type = string; default = "" }
