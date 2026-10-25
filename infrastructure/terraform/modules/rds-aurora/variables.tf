variable "name"              { type = string }
variable "aws_region"        { type = string }
variable "data_subnet_ids"   { type = list(string) }
variable "rds_sg_id"         { type = string }
variable "rds_proxy_sg_id"   { type = string }
variable "kms_key_arn"       { type = string }
variable "kms_key_id"        { type = string }
variable "database_name"     { type = string; default = "appdb" }
variable "master_username"   { type = string; default = "dbadmin" }
variable "engine_version"    { type = string; default = "16.2" }
variable "min_acu"           { type = number; default = 0.5 }
variable "max_acu"           { type = number; default = 128 }
variable "reader_count"      { type = number; default = 2 }
