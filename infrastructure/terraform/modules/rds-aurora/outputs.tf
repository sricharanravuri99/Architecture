output "cluster_endpoint"         { value = aws_rds_cluster.main.endpoint }
output "reader_endpoint"          { value = aws_rds_cluster.main.reader_endpoint }
output "cluster_id"               { value = aws_rds_cluster.main.cluster_identifier }
output "cluster_arn"              { value = aws_rds_cluster.main.arn }
output "proxy_endpoint"           { value = aws_db_proxy.main.endpoint }
output "secret_arn"               { value = aws_rds_cluster.main.master_user_secret[0].secret_arn }
output "database_name"            { value = aws_rds_cluster.main.database_name }
