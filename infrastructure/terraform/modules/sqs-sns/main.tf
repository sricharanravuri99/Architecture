################################################################################
# SQS + SNS — KMS Encrypted, DLQ, VPC Endpoint Policies
# Compliant with: HIPAA §164.312(e), PCI Req 4, NIST SC-8
################################################################################

variable "queues" {
  description = "Map of SQS queue configurations"
  type = map(object({
    fifo                     = optional(bool, false)
    visibility_timeout_secs  = optional(number, 30)
    message_retention_secs   = optional(number, 86400)
    delay_secs               = optional(number, 0)
    max_message_size         = optional(number, 262144)
    kms_key_arn              = string
    dlq_enabled              = optional(bool, true)
    dlq_max_receive_count    = optional(number, 3)
    tags                     = optional(map(string), {})
  }))
}

variable "topics" {
  description = "Map of SNS topic configurations"
  type = map(object({
    fifo        = optional(bool, false)
    kms_key_arn = string
    subscriptions = optional(list(object({
      protocol  = string
      endpoint  = string
    })), [])
    tags = optional(map(string), {})
  }))
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# SQS Dead-Letter Queues
################################################################################

resource "aws_sqs_queue" "dlq" {
  for_each                  = { for k, v in var.queues : k => v if v.dlq_enabled }
  name                      = "${var.name}-${each.key}-dlq${each.value.fifo ? ".fifo" : ""}"
  fifo_queue                = each.value.fifo
  kms_master_key_id         = each.value.kms_key_arn
  message_retention_seconds = 1209600 # 14 days — max for investigation
  sqs_managed_sse_enabled   = false

  tags = merge({ Name = "${var.name}-${each.key}-dlq", Purpose = "DLQ" }, each.value.tags)
}

################################################################################
# SQS Queues
################################################################################

resource "aws_sqs_queue" "main" {
  for_each                   = var.queues
  name                       = "${var.name}-${each.key}${each.value.fifo ? ".fifo" : ""}"
  fifo_queue                 = each.value.fifo
  content_based_deduplication = each.value.fifo ? true : null
  visibility_timeout_seconds = each.value.visibility_timeout_secs
  message_retention_seconds  = each.value.message_retention_secs
  delay_seconds              = each.value.delay_secs
  max_message_size           = each.value.max_message_size
  kms_master_key_id          = each.value.kms_key_arn
  sqs_managed_sse_enabled    = false

  dynamic "redrive_policy" {
    for_each = each.value.dlq_enabled ? [1] : []
    content {
      deadletter_target_arn = aws_sqs_queue.dlq[each.key].arn
      max_receive_count     = each.value.dlq_max_receive_count
    }
  }

  tags = merge({ Name = "${var.name}-${each.key}" }, each.value.tags)
}

resource "aws_sqs_queue_policy" "main" {
  for_each  = var.queues
  queue_url = aws_sqs_queue.main[each.key].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyNonTLS"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action   = "sqs:*"
        Resource = aws_sqs_queue.main[each.key].arn
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid    = "DenyPublicAccess"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action   = "sqs:*"
        Resource = aws_sqs_queue.main[each.key].arn
        Condition = {
          StringNotEquals = { "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id }
        }
      }
    ]
  })
}

################################################################################
# SNS Topics
################################################################################

resource "aws_sns_topic" "main" {
  for_each                    = var.topics
  name                        = "${var.name}-${each.key}${each.value.fifo ? ".fifo" : ""}"
  fifo_topic                  = each.value.fifo
  content_based_deduplication = each.value.fifo ? true : null
  kms_master_key_id           = each.value.kms_key_arn

  tags = merge({ Name = "${var.name}-${each.key}" }, each.value.tags)
}

resource "aws_sns_topic_policy" "main" {
  for_each = var.topics
  arn      = aws_sns_topic.main[each.key].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountPublish"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes"]
        Resource = aws_sns_topic.main[each.key].arn
      },
      {
        Sid    = "DenyNonTLS"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action   = "sns:*"
        Resource = aws_sns_topic.main[each.key].arn
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

resource "aws_sns_topic_subscription" "main" {
  for_each = merge([
    for topic_key, topic in var.topics : {
      for idx, sub in topic.subscriptions :
      "${topic_key}-${idx}" => merge(sub, { topic_arn = aws_sns_topic.main[topic_key].arn })
    }
  ]...)

  topic_arn = each.value.topic_arn
  protocol  = each.value.protocol
  endpoint  = each.value.endpoint
}
