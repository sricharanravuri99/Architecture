output "config_bucket_name"  { value = aws_s3_bucket.config.id }
output "recorder_name"       { value = aws_config_configuration_recorder.main.name }
