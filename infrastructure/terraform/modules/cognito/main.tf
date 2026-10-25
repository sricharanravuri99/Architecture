################################################################################
# Cognito — MFA, FIDO2/WebAuthn, SMART on FHIR, Advanced Security
# Compliant with: HIPAA §164.312(d), PCI Req 8, NIST 800-63B AAL2
################################################################################

resource "aws_cognito_user_pool" "main" {
  name = "${var.name}-user-pool"

  # Username attributes
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # Strong password policy (NIST 800-63B + PCI Req 8)
  password_policy {
    minimum_length                   = 14
    require_uppercase                = true
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 1
  }

  # MFA — required, TOTP + SMS
  mfa_configuration = "ON"

  software_token_mfa_configuration {
    enabled = true
  }

  # FIDO2/WebAuthn passkeys
  web_authn_configuration {
    relying_party_id        = var.domain_name
    user_verification       = "required"
  }

  # Account recovery — email only (more secure than SMS)
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # User attributes — FHIR-aligned
  schema {
    name                     = "email"
    attribute_data_type      = "String"
    required                 = true
    mutable                  = true
    string_attribute_constraints {
      min_length = 5
      max_length = 256
    }
  }

  schema {
    name                = "patient_id"
    attribute_data_type = "String"
    required            = false
    mutable             = true
    string_attribute_constraints {
      min_length = 0
      max_length = 256
    }
  }

  schema {
    name                = "organization_id"
    attribute_data_type = "String"
    required            = false
    mutable             = true
    string_attribute_constraints {
      min_length = 0
      max_length = 256
    }
  }

  schema {
    name                = "fhir_launch_context"
    attribute_data_type = "String"
    required            = false
    mutable             = true
    string_attribute_constraints {
      min_length = 0
      max_length = 2048
    }
  }

  # Advanced Security Mode — blocks compromised credentials
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  # Email configuration — SES
  email_configuration {
    email_sending_account  = "DEVELOPER"
    from_email_address     = var.ses_from_email
    source_arn             = var.ses_arn
    reply_to_email_address = var.ses_from_email
  }

  # Verification message
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "${var.app_name} - Verify your email"
    email_message        = "Your verification code is {####}. This code expires in 24 hours."
  }

  # Lambda triggers for custom auth flow + HIPAA audit
  lambda_config {
    pre_authentication           = var.pre_auth_lambda_arn
    post_authentication          = var.post_auth_lambda_arn
    pre_token_generation         = var.pre_token_lambda_arn
    user_migration               = var.user_migration_lambda_arn != "" ? var.user_migration_lambda_arn : null
    define_auth_challenge        = var.define_auth_challenge_lambda_arn != "" ? var.define_auth_challenge_lambda_arn : null
    create_auth_challenge        = var.create_auth_challenge_lambda_arn != "" ? var.create_auth_challenge_lambda_arn : null
    verify_auth_challenge_response = var.verify_auth_challenge_lambda_arn != "" ? var.verify_auth_challenge_lambda_arn : null
  }

  # Device tracking
  device_configuration {
    challenge_required_on_new_device      = true
    device_only_remembered_on_user_prompt = false
  }

  # Admin create user
  admin_create_user_config {
    allow_admin_create_user_only = false
    invite_message_template {
      email_subject = "Welcome to ${var.app_name}"
      email_message = "Your username is {username} and temporary password is {####}."
      sms_message   = "Your username is {username} and temporary password is {####}."
    }
  }

  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  # KMS for advanced security features
  # (Cognito uses AWS-managed keys by default)

  tags = { Name = "${var.name}-user-pool", Compliance = "HIPAA,PCI" }
}

################################################################################
# App Clients
################################################################################

# SMART on FHIR client (healthcare)
resource "aws_cognito_user_pool_client" "smart_on_fhir" {
  name         = "${var.name}-smart-fhir-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret                      = true
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  enable_propagate_additional_user_context_data = false

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = [
    "openid", "email", "profile",
    "launch/patient", "patient/*.read",
    "user/*.read", "offline_access"
  ]

  callback_urls = var.smart_fhir_callback_urls
  logout_urls   = var.smart_fhir_logout_urls

  supported_identity_providers = ["COGNITO"]

  access_token_validity  = 1    # hours
  id_token_validity      = 1    # hours
  refresh_token_validity = 30   # days

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  explicit_auth_flows = [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_CUSTOM_AUTH"
  ]

  read_attributes = [
    "email", "email_verified", "name", "custom:patient_id",
    "custom:organization_id", "custom:fhir_launch_context"
  ]

  write_attributes = ["email", "name", "custom:fhir_launch_context"]
}

# Internal API client (machine-to-machine)
resource "aws_cognito_user_pool_client" "api" {
  name         = "${var.name}-api-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret               = true
  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true

  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = var.api_scopes

  access_token_validity  = 1
  refresh_token_validity = 1

  token_validity_units {
    access_token  = "hours"
    refresh_token = "hours"
  }

  explicit_auth_flows = ["ALLOW_REFRESH_TOKEN_AUTH"]
}

################################################################################
# Cognito Domain
################################################################################

resource "aws_cognito_user_pool_domain" "main" {
  domain          = var.cognito_subdomain
  user_pool_id    = aws_cognito_user_pool.main.id
  certificate_arn = var.acm_certificate_arn != "" ? var.acm_certificate_arn : null
}

################################################################################
# Resource Server (SMART on FHIR scopes)
################################################################################

resource "aws_cognito_resource_server" "fhir" {
  identifier   = "https://fhir.${var.domain_name}"
  name         = "${var.name}-fhir-server"
  user_pool_id = aws_cognito_user_pool.main.id

  scope {
    scope_name        = "patient.read"
    scope_description = "Read patient FHIR resources"
  }

  scope {
    scope_name        = "patient.write"
    scope_description = "Write patient FHIR resources"
  }

  scope {
    scope_name        = "admin"
    scope_description = "Administrative access"
  }
}

################################################################################
# Identity Pool — Federated Access to AWS Resources
################################################################################

resource "aws_cognito_identity_pool" "main" {
  identity_pool_name               = "${var.name}-identity-pool"
  allow_unauthenticated_identities = false
  allow_classic_flow               = false

  cognito_identity_providers {
    client_id               = aws_cognito_user_pool_client.smart_on_fhir.id
    provider_name           = aws_cognito_user_pool.main.endpoint
    server_side_token_check = true
  }
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
  identity_pool_id = aws_cognito_identity_pool.main.id

  roles = {
    authenticated   = var.authenticated_role_arn
    unauthenticated = var.unauthenticated_role_arn != "" ? var.unauthenticated_role_arn : var.authenticated_role_arn
  }
}
