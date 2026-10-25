variable "name"                    { type = string }
variable "vpc_cidr"               { type = string; default = "10.0.0.0/16" }
variable "eks_pod_cidr"           { type = string; default = "" }
variable "aws_region"             { type = string }
variable "account_id"             { type = string }
variable "cluster_name"           { type = string; default = "main" }
variable "kms_key_arn"            { type = string }
variable "flow_log_s3_bucket_arn" { type = string; default = "" }
variable "enable_cde"             { type = bool; default = false }
variable "enable_dedicated_tenancy" { type = bool; default = false }
variable "payment_processor_cidrs" { type = list(string); default = [] }
