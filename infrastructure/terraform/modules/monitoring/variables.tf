variable "name"                  { type = string }
variable "cluster_name"          { type = string }
variable "kms_key_arn"           { type = string }
variable "eks_oidc_provider_arn" { type = string }
variable "eks_oidc_provider"     { type = string }
variable "private_subnet_ids"    { type = list(string) }
variable "grafana_sg_id"         { type = string }
variable "canary_sg_id"          { type = string }
variable "canary_bucket_name"    { type = string }
variable "alarm_sns_arn"         { type = string }
variable "pagerduty_endpoint"    { type = string; default = "" }
variable "rds_max_connections"   { type = number; default = 1000 }
