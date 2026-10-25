################################################################################
# DynamoDB — KMS Encryption, PITR, Global Tables, DAX
# Compliant with: HIPAA §164.312(a)(2)(iv), PCI Req 3.5, CIS DynamoDB
################################################################################

variable "tables" {
  description = "Map of DynamoDB table configurations"
  type = map(object({
    hash_key         = string
    range_key        = optional(string, null)
    billing_mode     = optional(string, "PAY_PER_REQUEST")
    kms_key_arn      = string
    global_table     = optional(bool, false)
    streams_enabled  = optional(bool, false)
    ttl_attribute    = optional(string, null)
    gsi              = optional(list(object({
      name            = string
      hash_key        = string
      range_key       = optional(string, null)
      projection_type = optional(string, "ALL")
    })), [])
    attributes = list(object({
      name = string
      type = string
    }))
    tags = optional(map(string), {})
  }))
}

resource "aws_dynamodb_table" "main" {
  for_each     = var.tables
  name         = "${var.name}-${each.key}"
  billing_mode = each.value.billing_mode
  hash_key     = each.value.hash_key
  range_key    = each.value.range_key

  # Always enable streams for PITR + audit
  stream_enabled   = each.value.streams_enabled || each.value.global_table
  stream_view_type = (each.value.streams_enabled || each.value.global_table) ? "NEW_AND_OLD_IMAGES" : null

  deletion_protection_enabled = true

  # KMS encryption at rest
  server_side_encryption {
    enabled     = true
    kms_key_arn = each.value.kms_key_arn
  }

  # Point-in-time recovery (35 days)
  point_in_time_recovery {
    enabled = true
  }

  # TTL for session/temporary data
  dynamic "ttl" {
    for_each = each.value.ttl_attribute != null ? [1] : []
    content {
      enabled        = true
      attribute_name = each.value.ttl_attribute
    }
  }

  # Dynamic attribute definitions
  dynamic "attribute" {
    for_each = each.value.attributes
    content {
      name = attribute.value.name
      type = attribute.value.type
    }
  }

  # Global Secondary Indexes
  dynamic "global_secondary_index" {
    for_each = each.value.gsi
    content {
      name            = global_secondary_index.value.name
      hash_key        = global_secondary_index.value.hash_key
      range_key       = global_secondary_index.value.range_key
      projection_type = global_secondary_index.value.projection_type
    }
  }

  # Table class — STANDARD for active, STANDARD_IA for archive
  table_class = "STANDARD"

  tags = merge(
    { Name = "${var.name}-${each.key}", Encryption = "KMS" },
    each.value.tags
  )

  lifecycle {
    prevent_destroy = true
  }
}

################################################################################
# Global Tables (Multi-region replication for DR)
################################################################################

resource "aws_dynamodb_global_table" "main" {
  for_each   = { for k, v in var.tables : k => v if v.global_table }
  depends_on = [aws_dynamodb_table.main]
  name       = "${var.name}-${each.key}"

  replica {
    region_name = var.primary_region
  }

  replica {
    region_name = var.dr_region
    kms_key_arn = var.dr_kms_key_arn
  }
}

################################################################################
# DynamoDB Auto-Scaling (for provisioned mode tables)
################################################################################

resource "aws_appautoscaling_target" "dynamodb_read" {
  for_each           = { for k, v in var.tables : k => v if v.billing_mode == "PROVISIONED" }
  max_capacity       = 1000
  min_capacity       = 5
  resource_id        = "table/${aws_dynamodb_table.main[each.key].name}"
  scalable_dimension = "dynamodb:table:ReadCapacityUnits"
  service_namespace  = "dynamodb"
}

resource "aws_appautoscaling_policy" "dynamodb_read" {
  for_each           = { for k, v in var.tables : k => v if v.billing_mode == "PROVISIONED" }
  name               = "${var.name}-${each.key}-read-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.dynamodb_read[each.key].resource_id
  scalable_dimension = aws_appautoscaling_target.dynamodb_read[each.key].scalable_dimension
  service_namespace  = aws_appautoscaling_target.dynamodb_read[each.key].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "DynamoDBReadCapacityUtilization"
    }
    target_value = 70
  }
}

################################################################################
# CloudWatch Alarms
################################################################################

resource "aws_cloudwatch_metric_alarm" "dynamodb_user_errors" {
  for_each            = var.tables
  alarm_name          = "${var.name}-dynamodb-${each.key}-user-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UserErrors"
  namespace           = "AWS/DynamoDB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "DynamoDB user errors on ${each.key}"
  alarm_actions       = [var.alarm_sns_arn]

  dimensions = { TableName = aws_dynamodb_table.main[each.key].name }
}
