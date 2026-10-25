output "domain_endpoint"  { value = aws_opensearch_domain.main.endpoint }
output "domain_arn"       { value = aws_opensearch_domain.main.arn }
output "kibana_endpoint"  { value = aws_opensearch_domain.main.kibana_endpoint }
