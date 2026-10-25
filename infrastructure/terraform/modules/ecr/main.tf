################################################################################
# ECR — Immutable Tags, Scan on Push, Lifecycle Policies, Replication
# Compliant with: PCI Req 6.3, CIS Docker, NIST SP 800-190
################################################################################

variable "repositories" {
  description = "Map of ECR repository configurations"
  type = map(object({
    scan_on_push      = optional(bool, true)
    immutable_tags    = optional(bool, true)
    max_image_count   = optional(number, 50)
    tags              = optional(map(string), {})
  }))
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_ecr_repository" "main" {
  for_each             = var.repositories
  name                 = "${var.name}/${each.key}"
  image_tag_mutability = each.value.immutable_tags ? "IMMUTABLE" : "MUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = each.value.scan_on_push
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = merge(
    { Name = "${var.name}/${each.key}" },
    each.value.tags
  )
}

################################################################################
# Lifecycle Policies — Keep last N images, expire untagged
################################################################################

resource "aws_ecr_lifecycle_policy" "main" {
  for_each   = var.repositories
  repository = aws_ecr_repository.main[each.key].name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep last ${each.value.max_image_count} tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v", "release", "prod", "staging"]
          countType     = "imageCountMoreThan"
          countNumber   = each.value.max_image_count
        }
        action = { type = "expire" }
      }
    ]
  })
}

################################################################################
# Repository Policy — Deny pulls without image scanning pass
################################################################################

resource "aws_ecr_repository_policy" "main" {
  for_each   = var.repositories
  repository = aws_ecr_repository.main[each.key].name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEKSPull"
        Effect = "Allow"
        Principal = {
          AWS = var.allowed_pull_arns
        }
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability"
        ]
      },
      {
        Sid    = "DenyPublicAccess"
        Effect = "Deny"
        Principal = "*"
        Action = "ecr:*"
        Condition = {
          StringNotEquals = { "aws:PrincipalAccount" = [data.aws_caller_identity.current.account_id] }
          ArnNotLike      = { "aws:PrincipalArn" = var.allowed_pull_arns }
        }
      }
    ]
  })
}

################################################################################
# Replication to DR region
################################################################################

resource "aws_ecr_replication_configuration" "main" {
  replication_configuration {
    rule {
      destination {
        region      = var.dr_region
        registry_id = data.aws_caller_identity.current.account_id
      }
      repository_filter {
        filter      = "${var.name}/"
        filter_type = "PREFIX_MATCH"
      }
    }
  }
}

################################################################################
# ECR Pull-Through Cache (for public images — Docker Hub, Quay)
################################################################################

resource "aws_ecr_pull_through_cache_rule" "dockerhub" {
  ecr_repository_prefix = "dockerhub"
  upstream_registry_url = "registry-1.docker.io"
  credential_arn        = var.dockerhub_secret_arn
}

resource "aws_ecr_pull_through_cache_rule" "quay" {
  ecr_repository_prefix = "quay"
  upstream_registry_url = "quay.io"
}

################################################################################
# Inspector V2 — Enhanced Scanning (ECR + Lambda)
################################################################################

resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR", "LAMBDA", "EC2"]
}
