output "permission_boundary_arn"    { value = aws_iam_policy.permission_boundary.arn }
output "app_backend_role_arn"       { value = aws_iam_role.app_backend.arn }
output "external_secrets_role_arn"  { value = aws_iam_role.external_secrets.arn }
output "fluentbit_role_arn"         { value = aws_iam_role.fluentbit.arn }
output "break_glass_role_arn"       { value = aws_iam_role.break_glass.arn }
output "access_analyzer_arn"        { value = aws_accessanalyzer_analyzer.main.arn }
