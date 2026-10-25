################################################################################
# Aurora PostgreSQL — Multi-AZ, RDS Proxy, Advanced Auditing
# Compliant with: HIPAA §164.312, PCI-DSS Req 3/10, SOX ITGC
################################################################################

resource "aws_db_subnet_group" "main" {
  name        = "${var.name}-aurora-subnet-group"
  subnet_ids  = var.data_subnet_ids
  description = "Aurora subnet group — data tier only"
  tags        = { Name = "${var.name}-aurora-subnet-group" }
}

resource "aws_rds_cluster_parameter_group" "main" {
  name        = "${var.name}-aurora-pg16"
  family      = "aurora-postgresql16"
  description = "Hardened Aurora PostgreSQL parameter group"

  # Force TLS connections (HIPAA §164.312(e)(1), PCI Req 4)
  parameter { name = "rds.force_ssl"; value = "1" }

  # Audit logging — all connections, disconnections, errors (PCI Req 10)
  parameter { name = "pgaudit.log";           value = "all" }
  parameter { name = "pgaudit.log_catalog";   value = "0" }
  parameter { name = "pgaudit.log_parameter"; value = "0" }
  parameter { name = "shared_preload_libraries"; value = "pgaudit" }

  # Connection security
  parameter { name = "password_encryption";    value = "scram-sha-256" }
  parameter { name = "ssl_min_protocol_version"; value = "TLSv1.2" }

  # Log slow queries
  parameter { name = "log_min_duration_statement"; value = "1000" }  # 1 second
  parameter { name = "log_connections";             value = "1" }
  parameter { name = "log_disconnections";          value = "1" }
  parameter { name = "log_lock_waits";              value = "1" }
  parameter { name = "log_temp_files";              value = "0" }

  tags = { Name = "${var.name}-aurora-params" }
}

resource "aws_rds_cluster" "main" {
  cluster_identifier     = "${var.name}-aurora"
  engine                 = "aurora-postgresql"
  engine_version         = var.engine_version
  database_name          = var.database_name
  master_username        = var.master_username
  manage_master_user_password = true # AWS manages password in Secrets Manager
  master_user_secret_kms_key_id = var.kms_key_id

  db_subnet_group_name            = aws_db_subnet_group.main.name
  vpc_security_group_ids          = [var.rds_sg_id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.main.name

  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  backup_retention_period      = 35 # Maximum — HIPAA requires 6yr, use exports for long-term
  preferred_backup_window      = "03:00-04:00"
  preferred_maintenance_window = "sun:05:00-sun:06:00"
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${var.name}-aurora-final-snapshot"
  copy_tags_to_snapshot        = true
  deletion_protection          = true

  # CloudWatch logs for audit, error, general, slowquery (PCI Req 10)
  enabled_cloudwatch_logs_exports = ["postgresql"]

  # Serverless v2 auto-scaling
  serverlessv2_scaling_configuration {
    min_capacity = var.min_acu
    max_capacity = var.max_acu
  }

  # Enhanced monitoring
  monitoring_interval      = 5
  monitoring_role_arn      = aws_iam_role.rds_enhanced_monitoring.arn
  performance_insights_enabled = true
  performance_insights_kms_key_id = var.kms_key_arn
  performance_insights_retention_period = 731 # 2 years

  apply_immediately   = false
  tags = {
    Name       = "${var.name}-aurora"
    Compliance = "HIPAA,PCI-DSS,SOX"
  }
}

# Writer instance
resource "aws_rds_cluster_instance" "writer" {
  identifier         = "${var.name}-aurora-writer"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  db_subnet_group_name      = aws_db_subnet_group.main.name
  db_parameter_group_name   = aws_rds_cluster_parameter_group.main.name
  publicly_accessible       = false
  auto_minor_version_upgrade = true

  monitoring_interval      = 5
  monitoring_role_arn      = aws_iam_role.rds_enhanced_monitoring.arn
  performance_insights_enabled = true
  performance_insights_kms_key_id = var.kms_key_arn

  tags = { Name = "${var.name}-aurora-writer" }
}

# Reader instances across AZs
resource "aws_rds_cluster_instance" "readers" {
  count              = var.reader_count
  identifier         = "${var.name}-aurora-reader-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  db_subnet_group_name    = aws_db_subnet_group.main.name
  publicly_accessible     = false
  promotion_tier          = count.index + 1

  monitoring_interval  = 5
  monitoring_role_arn  = aws_iam_role.rds_enhanced_monitoring.arn
  performance_insights_enabled = true
  performance_insights_kms_key_id = var.kms_key_arn

  tags = { Name = "${var.name}-aurora-reader-${count.index + 1}" }
}

################################################################################
# RDS Proxy — Connection pooling, IAM auth, secret rotation support
################################################################################
resource "aws_db_proxy" "main" {
  name                   = "${var.name}-rds-proxy"
  debug_logging          = false
  engine_family          = "POSTGRESQL"
  idle_client_timeout    = 1800
  require_tls            = true
  role_arn               = aws_iam_role.rds_proxy.arn
  vpc_security_group_ids = [var.rds_proxy_sg_id]
  vpc_subnet_ids         = var.data_subnet_ids

  auth {
    auth_scheme               = "SECRETS"
    description               = "Aurora master credentials"
    iam_auth                  = "REQUIRED" # IAM database auth required (PCI Req 8)
    secret_arn                = aws_rds_cluster.main.master_user_secret[0].secret_arn
  }

  tags = { Name = "${var.name}-rds-proxy" }
}

resource "aws_db_proxy_default_target_group" "main" {
  db_proxy_name = aws_db_proxy.main.name

  connection_pool_config {
    connection_borrow_timeout    = 120
    max_connections_percent      = 80
    max_idle_connections_percent = 50
  }
}

resource "aws_db_proxy_target" "main" {
  db_cluster_identifier = aws_rds_cluster.main.cluster_identifier
  db_proxy_name         = aws_db_proxy.main.name
  target_group_name     = aws_db_proxy_default_target_group.main.name
}

################################################################################
# IAM Roles
################################################################################
resource "aws_iam_role" "rds_enhanced_monitoring" {
  name = "${var.name}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "monitoring.rds.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  role       = aws_iam_role.rds_enhanced_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_iam_role" "rds_proxy" {
  name = "${var.name}-rds-proxy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "rds.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "rds_proxy" {
  name = "${var.name}-rds-proxy-policy"
  role = aws_iam_role.rds_proxy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [aws_rds_cluster.main.master_user_secret[0].secret_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.kms_key_arn]
        Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.aws_region}.amazonaws.com" } }
      }
    ]
  })
}

# Subnet group for parameter group (reuse data subnets)
resource "aws_rds_cluster_parameter_group" "global" {
  name        = "${var.name}-aurora-global-pg16"
  family      = "aurora-postgresql16"
  description = "Global cluster parameter group"
  tags        = { Name = "${var.name}-aurora-global-params" }
}
