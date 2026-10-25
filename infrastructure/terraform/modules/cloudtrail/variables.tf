variable "name"                    { type = string }
variable "cloudtrail_kms_key_arn"  { type = string }
variable "security_sns_arn"        { type = string }
variable "is_organization_trail"   { type = bool; default = true }
variable "log_retention_days"      { type = number; default = 2555 } # 7 years
