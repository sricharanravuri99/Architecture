output "bucket_ids"   { value = { for k, v in aws_s3_bucket.main : k => v.id } }
output "bucket_arns"  { value = { for k, v in aws_s3_bucket.main : k => v.arn } }
output "replica_arns" { value = { for k, v in aws_s3_bucket.replica : k => v.arn } }
