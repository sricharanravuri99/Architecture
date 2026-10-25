variable "name"                    { type = string }
variable "kms_key_arn"             { type = string }
variable "dr_kms_key_arn"          { type = string }
variable "backup_sns_arn"          { type = string }
variable "report_bucket_name"      { type = string }
variable "critical_resource_arns"  { type = list(string); default = [] }
