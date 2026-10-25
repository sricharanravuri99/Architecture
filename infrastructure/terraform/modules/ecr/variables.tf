variable "name"               { type = string }
variable "kms_key_arn"        { type = string }
variable "allowed_pull_arns"  { type = list(string) }
variable "dr_region"          { type = string; default = "us-west-2" }
variable "dockerhub_secret_arn" { type = string; default = "" }
