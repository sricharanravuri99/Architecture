output "user_pool_id"          { value = aws_cognito_user_pool.main.id }
output "user_pool_arn"         { value = aws_cognito_user_pool.main.arn }
output "user_pool_endpoint"    { value = aws_cognito_user_pool.main.endpoint }
output "smart_fhir_client_id"  { value = aws_cognito_user_pool_client.smart_on_fhir.id }
output "api_client_id"         { value = aws_cognito_user_pool_client.api.id }
output "identity_pool_id"      { value = aws_cognito_identity_pool.main.id }
output "domain"                { value = aws_cognito_user_pool_domain.main.domain }
