variable "name"                              { type = string }
variable "app_name"                           { type = string }
variable "domain_name"                        { type = string }
variable "cognito_subdomain"                  { type = string }
variable "ses_from_email"                     { type = string }
variable "ses_arn"                            { type = string }
variable "acm_certificate_arn"               { type = string; default = "" }
variable "smart_fhir_callback_urls"           { type = list(string) }
variable "smart_fhir_logout_urls"             { type = list(string) }
variable "api_scopes"                         { type = list(string); default = ["openid"] }
variable "authenticated_role_arn"             { type = string }
variable "unauthenticated_role_arn"           { type = string; default = "" }
variable "pre_auth_lambda_arn"               { type = string; default = "" }
variable "post_auth_lambda_arn"              { type = string; default = "" }
variable "pre_token_lambda_arn"              { type = string; default = "" }
variable "user_migration_lambda_arn"         { type = string; default = "" }
variable "define_auth_challenge_lambda_arn"  { type = string; default = "" }
variable "create_auth_challenge_lambda_arn"  { type = string; default = "" }
variable "verify_auth_challenge_lambda_arn"  { type = string; default = "" }
