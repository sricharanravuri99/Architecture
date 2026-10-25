variable "name"                       { type = string }
variable "hsm_subnet_ids"             { type = list(string) }
variable "key_store_password"         { type = string; sensitive = true }
variable "hsm_trust_anchor_certificate" { type = string }
variable "security_sns_arn"           { type = string }
