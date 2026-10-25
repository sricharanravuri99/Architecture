output "primary_vault_arn"  { value = aws_backup_vault.primary.arn }
output "dr_vault_arn"       { value = aws_backup_vault.dr.arn }
output "backup_plan_id"     { value = aws_backup_plan.main.id }
output "backup_role_arn"    { value = aws_iam_role.backup.arn }
