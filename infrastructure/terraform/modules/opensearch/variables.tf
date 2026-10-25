variable "name"                  { type = string }
variable "instance_type"         { type = string; default = "r6g.large.search" }
variable "master_instance_type"  { type = string; default = "r6g.large.search" }
variable "instance_count"        { type = number; default = 3 }
variable "volume_size_gb"        { type = number; default = 100 }
variable "kms_key_arn"           { type = string }
variable "opensearch_sg_id"      { type = string }
variable "data_subnet_ids"       { type = list(string) }
variable "master_user_arn"       { type = string }
variable "allowed_iam_arns"      { type = list(string) }
variable "alarm_sns_arn"         { type = string }
