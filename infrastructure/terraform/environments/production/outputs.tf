################################################################################
# Production Environment Outputs
################################################################################

output "vpc_id"                   { value = module.vpc.vpc_id }
output "eks_cluster_name"         { value = module.eks.cluster_name }
output "eks_cluster_endpoint"     { value = module.eks.cluster_endpoint; sensitive = true }
output "rds_proxy_endpoint"       { value = module.rds.proxy_endpoint; sensitive = true }
output "rds_secret_arn"           { value = module.rds.secret_arn; sensitive = true }
output "redis_primary_endpoint"   { value = module.elasticache.primary_endpoint; sensitive = true }
output "opensearch_endpoint"      { value = module.opensearch.domain_endpoint; sensitive = true }
output "cloudfront_domain"        { value = module.cloudfront.distribution_domain }
output "alb_dns_name"             { value = aws_lb.main.dns_name }
output "cognito_user_pool_id"     { value = module.cognito.user_pool_id }
output "cognito_smart_client_id"  { value = module.cognito.smart_fhir_client_id }
output "prometheus_endpoint"      { value = module.monitoring.prometheus_endpoint; sensitive = true }
output "grafana_endpoint"         { value = module.monitoring.grafana_endpoint }
output "ecr_repository_urls"      { value = module.ecr.repository_urls }
output "security_sns_arn"         { value = aws_sns_topic.security.arn }
output "break_glass_role_arn"     { value = module.iam.break_glass_role_arn }
output "permission_boundary_arn"  { value = module.iam.permission_boundary_arn }
