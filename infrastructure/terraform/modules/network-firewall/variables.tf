variable "name"                { type = string }
variable "vpc_id"              { type = string }
variable "firewall_subnet_ids" { type = list(string) }
variable "kms_key_arn"         { type = string }
variable "allowed_domains"     { type = list(string); default = [] }
