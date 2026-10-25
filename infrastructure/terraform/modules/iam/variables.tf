variable "name"                    { type = string }
variable "eks_oidc_provider_arn"   { type = string }
variable "eks_oidc_provider"       { type = string }
variable "app_namespace"           { type = string; default = "app" }
variable "app_kms_key_arns"        { type = list(string) }
variable "security_admin_arns"     { type = list(string) }
variable "break_glass_external_id" { type = string; sensitive = true }
variable "security_sns_arn"        { type = string }
variable "is_organization"         { type = bool; default = true }
