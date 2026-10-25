output "cluster_id"         { value = aws_cloudhsm_v2_cluster.main.cluster_id }
output "cluster_state"      { value = aws_cloudhsm_v2_cluster.main.cluster_state }
output "custom_key_store_id" { value = aws_kms_custom_key_store.main.id }
output "security_group_id"  { value = aws_cloudhsm_v2_cluster.main.security_group_id }
