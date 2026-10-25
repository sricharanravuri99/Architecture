variable "name"                 { type = string }
variable "scope"                { type = string; default = "REGIONAL" } # REGIONAL or CLOUDFRONT
variable "blocked_ip_list"      { type = list(string); default = [] }
variable "allowed_ip_list"      { type = list(string); default = [] }
variable "allowed_countries"    { type = list(string); default = [] }
variable "rate_limit_per_5min"  { type = number; default = 2000 }
variable "enable_bot_control"   { type = bool; default = true }
variable "log_destination_arn"  { type = string }
variable "alb_arn"              { type = string; default = "" }
variable "api_gateway_arn"      { type = string; default = "" }
