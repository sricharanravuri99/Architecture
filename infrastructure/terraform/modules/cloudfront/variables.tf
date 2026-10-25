variable "name"                        { type = string }
variable "s3_bucket_regional_domain"    { type = string }
variable "alb_dns_name"                 { type = string }
variable "waf_web_acl_arn"              { type = string }
variable "acm_certificate_arn"          { type = string }
variable "cloudfront_origin_secret"     { type = string; sensitive = true }
variable "log_bucket_name"              { type = string }
variable "domain_aliases"               { type = list(string) }
variable "domain_name"                  { type = string }
variable "allowed_countries"            { type = list(string); default = [] }
variable "route53_zone_id"              { type = string }
variable "origin_shield_region"         { type = string; default = "us-east-1" }
