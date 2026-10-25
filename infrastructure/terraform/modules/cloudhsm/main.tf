################################################################################
# CloudHSM — FIPS 140-2 Level 3, 3-node cluster across AZs
# Required for: PHI CMK, PAN CMK (CloudHSM-backed KMS custom key store)
# Compliant with: HIPAA §164.312(a)(2)(iv), PCI Req 3.5, FIPS 140-2 L3
################################################################################

data "aws_availability_zones" "available" {}

resource "aws_cloudhsm_v2_cluster" "main" {
  hsm_type   = "hsm1.medium"
  subnet_ids = var.hsm_subnet_ids

  tags = {
    Name       = "${var.name}-cloudhsm"
    Compliance = "HIPAA,PCI,FIPS-140-2-L3"
    Dual-Control = "required"
  }
}

# 3 HSM nodes — one per AZ for HA
resource "aws_cloudhsm_v2_hsm" "az1" {
  cluster_id        = aws_cloudhsm_v2_cluster.main.cluster_id
  availability_zone = data.aws_availability_zones.available.names[0]
}

resource "aws_cloudhsm_v2_hsm" "az2" {
  cluster_id        = aws_cloudhsm_v2_cluster.main.cluster_id
  availability_zone = data.aws_availability_zones.available.names[1]

  depends_on = [aws_cloudhsm_v2_hsm.az1]
}

resource "aws_cloudhsm_v2_hsm" "az3" {
  cluster_id        = aws_cloudhsm_v2_cluster.main.cluster_id
  availability_zone = data.aws_availability_zones.available.names[2]

  depends_on = [aws_cloudhsm_v2_hsm.az2]
}

################################################################################
# KMS Custom Key Store backed by CloudHSM
# NOTE: After CloudHSM cluster initialization and certificate upload,
# you must manually connect the key store before creating CMKs.
# See: aws kms connect-custom-key-store --custom-key-store-id <id>
################################################################################

resource "aws_kms_custom_key_store" "main" {
  cloud_hsm_cluster_id  = aws_cloudhsm_v2_cluster.main.cluster_id
  custom_key_store_name = "${var.name}-hsm-key-store"
  key_store_password    = var.key_store_password # Crypto Officer password

  # trust_anchor_certificate must be the cluster's issuing certificate
  trust_anchor_certificate = var.hsm_trust_anchor_certificate

  lifecycle {
    ignore_changes = [trust_anchor_certificate]
  }
}

################################################################################
# CloudWatch Alarm — HSM availability
################################################################################

resource "aws_cloudwatch_metric_alarm" "hsm_instances" {
  alarm_name          = "${var.name}-cloudhsm-instance-count"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HsmUnhealthy"
  namespace           = "AWS/CloudHSM"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CloudHSM has unhealthy HSM instances — key operations may fail"
  alarm_actions       = [var.security_sns_arn]

  dimensions = { ClusterId = aws_cloudhsm_v2_cluster.main.cluster_id }
}
