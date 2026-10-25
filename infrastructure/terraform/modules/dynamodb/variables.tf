variable "name"           { type = string }
variable "primary_region" { type = string; default = "us-east-1" }
variable "dr_region"      { type = string; default = "us-west-2" }
variable "dr_kms_key_arn" { type = string; default = "" }
variable "alarm_sns_arn"  { type = string }
