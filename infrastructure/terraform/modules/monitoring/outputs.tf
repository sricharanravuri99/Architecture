output "prometheus_workspace_id"    { value = aws_prometheus_workspace.main.id }
output "prometheus_workspace_arn"   { value = aws_prometheus_workspace.main.arn }
output "prometheus_endpoint"        { value = aws_prometheus_workspace.main.prometheus_endpoint }
output "grafana_workspace_id"       { value = aws_grafana_workspace.main.id }
output "grafana_endpoint"           { value = aws_grafana_workspace.main.endpoint }
output "alarms_sns_arn"             { value = aws_sns_topic.alarms.arn }
output "adot_role_arn"              { value = aws_iam_role.adot.arn }
