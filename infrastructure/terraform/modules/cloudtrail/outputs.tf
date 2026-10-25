output "trail_arn"        { value = aws_cloudtrail.organization.arn }
output "s3_bucket_name"  { value = aws_s3_bucket.cloudtrail.id }
output "log_group_name"  { value = aws_cloudwatch_log_group.cloudtrail.name }
