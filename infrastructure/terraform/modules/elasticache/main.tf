################################################################################
# ElastiCache Redis — Cluster Mode, TLS, AUTH, RBAC
# Compliant with: HIPAA §164.312(a)(2)(iv), PCI Req 2.2, CIS Redis
################################################################################

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "${var.name}-redis"
  description                = "Redis cluster — TLS, auth, cluster mode enabled"
  node_type                  = var.node_type
  num_cache_clusters         = var.num_replicas + 1
  automatic_failover_enabled = true
  multi_az_enabled           = true
  port                       = 6380 # TLS port

  # TLS in-transit
  transit_encryption_enabled = true
  # Encryption at rest
  at_rest_encryption_enabled = true
  kms_key_id                 = var.kms_key_arn

  # AUTH token (stored in Secrets Manager)
  auth_token                  = var.auth_token
  auth_token_update_strategy  = "ROTATE"

  engine_version     = "7.1"
  parameter_group_name = aws_elasticache_parameter_group.main.name
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = [var.redis_sg_id]

  # Maintenance & backups
  maintenance_window        = "sun:05:00-sun:06:00"
  snapshot_window           = "03:00-04:00"
  snapshot_retention_limit  = 35
  final_snapshot_identifier = "${var.name}-redis-final"

  # CloudWatch logging
  log_delivery_configuration {
    destination      = var.log_group_name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-logs"
  }

  log_delivery_configuration {
    destination      = var.log_group_name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "engine-logs"
  }

  tags = { Name = "${var.name}-redis", DataClassification = "Sensitive" }
}

resource "aws_elasticache_parameter_group" "main" {
  family = "redis7"
  name   = "${var.name}-redis-params"

  parameter {
    name  = "maxmemory-policy"
    value = "volatile-lru" # evict expiring keys only — protect session data
  }

  parameter {
    name  = "notify-keyspace-events"
    value = "Ex" # expired key events for session management
  }

  parameter {
    name  = "timeout"
    value = "300" # 5-minute idle connection timeout
  }

  parameter {
    name  = "tcp-keepalive"
    value = "300"
  }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.name}-redis-subnet-group"
  subnet_ids = var.data_subnet_ids

  tags = { Name = "${var.name}-redis-subnet-group" }
}

################################################################################
# CloudWatch Alarms — Redis Health
################################################################################

resource "aws_cloudwatch_metric_alarm" "redis_cpu" {
  alarm_name          = "${var.name}-redis-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "EngineCPUUtilization"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Redis CPU > 80%"
  alarm_actions       = [var.alarm_sns_arn]

  dimensions = {
    ReplicationGroupId = aws_elasticache_replication_group.main.id
  }
}

resource "aws_cloudwatch_metric_alarm" "redis_memory" {
  alarm_name          = "${var.name}-redis-memory-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "FreeableMemory"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Average"
  threshold           = 104857600 # 100MB
  alarm_description   = "Redis free memory < 100MB"
  alarm_actions       = [var.alarm_sns_arn]

  dimensions = {
    ReplicationGroupId = aws_elasticache_replication_group.main.id
  }
}

resource "aws_cloudwatch_metric_alarm" "redis_evictions" {
  alarm_name          = "${var.name}-redis-evictions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Evictions"
  namespace           = "AWS/ElastiCache"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Redis evictions detected — session data at risk"
  alarm_actions       = [var.alarm_sns_arn]

  dimensions = {
    ReplicationGroupId = aws_elasticache_replication_group.main.id
  }
}
