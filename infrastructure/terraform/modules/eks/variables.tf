variable "cluster_name"               { type = string }
variable "kubernetes_version"          { type = string; default = "1.30" }
variable "aws_region"                  { type = string }
variable "private_subnet_ids"          { type = list(string) }
variable "control_plane_sg_id"         { type = string }
variable "node_sg_id"                  { type = string }
variable "kms_key_arn"                 { type = string }
variable "bottlerocket_ami_id"         { type = string; default = "" }
variable "service_ipv4_cidr"           { type = string; default = "172.20.0.0/16" }
variable "max_pods_per_node"           { type = number; default = 110 }
variable "system_node_instance_types"  { type = list(string); default = ["m6i.xlarge", "m6a.xlarge"] }
variable "addon_versions" {
  type = map(string)
  default = {
    "vpc-cni"              = "v1.18.1-eksbuild.1"
    "coredns"              = "v1.11.1-eksbuild.8"
    "kube-proxy"           = "v1.30.0-eksbuild.3"
    "aws-ebs-csi-driver"   = "v1.30.0-eksbuild.1"
    "eks-pod-identity-agent" = "v1.3.0-eksbuild.1"
  }
}
