variable "name"                  { type = string }
variable "cloudhsm_key_store_id" { type = string; default = "" }
variable "phi_role_arns"         { type = list(string); default = [] }
variable "cde_role_arns"         { type = list(string); default = [] }
