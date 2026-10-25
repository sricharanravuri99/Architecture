variable "name"             { type = string }
variable "node_type"        { type = string; default = "cache.r7g.large" }
variable "num_replicas"     { type = number; default = 2 }
variable "kms_key_arn"      { type = string }
variable "auth_token"       { type = string; sensitive = true }
variable "redis_sg_id"      { type = string }
variable "data_subnet_ids"  { type = list(string) }
variable "log_group_name"   { type = string }
variable "alarm_sns_arn"    { type = string }
