variable "name"                    { type = string }
variable "vpc_id"                  { type = string }
variable "vpc_cidr"                { type = string }
variable "vpc_endpoint_sg_id"      { type = string }
variable "enable_cde"              { type = bool; default = false }
variable "payment_processor_cidrs" { type = list(string); default = [] }
