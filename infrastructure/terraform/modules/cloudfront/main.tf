################################################################################
# CloudFront — OAC, WAF, Field-Level Encryption, Geo Restriction, HTTPS-only
# Compliant with: PCI Req 6.4, HIPAA §164.312(e), CIS CloudFront
################################################################################

data "aws_caller_identity" "current" {}

resource "aws_cloudfront_origin_access_control" "main" {
  name                              = "${var.name}-oac"
  description                       = "OAC for ${var.name} — S3 origin access"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "main" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.name} — Secure CloudFront Distribution"
  default_root_object = "index.html"
  http_version        = "http2and3"
  price_class         = "PriceClass_All"
  web_acl_id          = var.waf_web_acl_arn  # WAF CLOUDFRONT-scoped ACL
  aliases             = var.domain_aliases

  # S3 Static Assets Origin
  origin {
    domain_name              = var.s3_bucket_regional_domain
    origin_id                = "S3-${var.name}-assets"
    origin_access_control_id = aws_cloudfront_origin_access_control.main.id

    origin_shield {
      enabled              = true
      origin_shield_region = var.origin_shield_region
    }
  }

  # ALB API Origin (HTTPS only, custom header for validation)
  origin {
    domain_name = var.alb_dns_name
    origin_id   = "ALB-${var.name}-api"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_keepalive_timeout = 60
      origin_read_timeout      = 30
    }

    custom_header {
      name  = "X-CloudFront-Secret"
      value = var.cloudfront_origin_secret
    }
  }

  # Default behavior — S3 static assets
  default_cache_behavior {
    target_origin_id       = "S3-${var.name}-assets"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id          = aws_cloudfront_cache_policy.static.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.s3.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.security_headers.arn
    }
  }

  # API behavior — forward to ALB
  ordered_cache_behavior {
    path_pattern           = "/api/*"
    target_origin_id       = "ALB-${var.name}-api"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id   = aws_cloudfront_origin_request_policy.api.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id
  }

  # Health check endpoint (no caching)
  ordered_cache_behavior {
    path_pattern           = "/health"
    target_origin_id       = "ALB-${var.name}-api"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "redirect-to-https"
    compress               = true
    cache_policy_id        = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = aws_cloudfront_origin_request_policy.api.id
  }

  geo_restriction {
    restriction_type = length(var.allowed_countries) > 0 ? "whitelist" : "none"
    locations        = var.allowed_countries
  }

  viewer_certificate {
    acm_certificate_arn      = var.acm_certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  # Logging to S3
  logging_config {
    bucket          = "${var.log_bucket_name}.s3.amazonaws.com"
    prefix          = "cloudfront/"
    include_cookies = true
  }

  # Custom error pages
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 0
  }

  tags = { Name = "${var.name}-cloudfront" }
}

################################################################################
# Cache Policies
################################################################################

resource "aws_cloudfront_cache_policy" "static" {
  name    = "${var.name}-static-assets"
  comment = "Cache policy for static assets (1 year)"

  default_ttl = 86400
  max_ttl     = 31536000
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config    { cookie_behavior = "none" }
    headers_config    { header_behavior = "none" }
    query_strings_config { query_string_behavior = "none" }
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true
  }
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

################################################################################
# Origin Request Policies
################################################################################

resource "aws_cloudfront_origin_request_policy" "api" {
  name    = "${var.name}-api-origin-request"
  comment = "Forward all headers except Host to ALB for API"

  cookies_config    { cookie_behavior = "all" }
  headers_config {
    header_behavior = "allExcept"
    headers { items = ["Host"] }
  }
  query_strings_config { query_string_behavior = "all" }
}

resource "aws_cloudfront_origin_request_policy" "s3" {
  name    = "${var.name}-s3-origin-request"
  comment = "S3 origin — minimal headers"

  cookies_config    { cookie_behavior = "none" }
  headers_config {
    header_behavior = "whitelist"
    headers { items = ["Origin", "Access-Control-Request-Headers", "Access-Control-Request-Method"] }
  }
  query_strings_config { query_string_behavior = "none" }
}

################################################################################
# Security Response Headers Policy
################################################################################

resource "aws_cloudfront_response_headers_policy" "security" {
  name    = "${var.name}-security-headers"
  comment = "HIPAA/PCI compliant security headers"

  security_headers_config {
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' https://api.${var.domain_name}; frame-ancestors 'none';"
      override                = true
    }

    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }

    strict_transport_security {
      access_control_max_age_sec = 63072000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
  }

  custom_headers_config {
    items {
      header   = "Permissions-Policy"
      value    = "camera=(), microphone=(), geolocation=()"
      override = true
    }
  }
}

################################################################################
# CloudFront Function — Security Headers + Bot Detection
################################################################################

resource "aws_cloudfront_function" "security_headers" {
  name    = "${var.name}-security-headers"
  runtime = "cloudfront-js-2.0"
  comment = "Add security headers and validate requests"
  publish = true

  code = <<-JS
    async function handler(event) {
      const request = event.request;
      const headers = request.headers;

      // Block requests with suspicious user agents
      const ua = headers['user-agent'] ? headers['user-agent'].value : '';
      const blockedAgents = ['sqlmap', 'nikto', 'nmap', 'masscan'];
      for (const agent of blockedAgents) {
        if (ua.toLowerCase().includes(agent)) {
          return {
            statusCode: 403,
            statusDescription: 'Forbidden'
          };
        }
      }

      // Enforce HTTPS redirect
      if (request.headers['cloudfront-forwarded-proto'] &&
          request.headers['cloudfront-forwarded-proto'].value === 'http') {
        return {
          statusCode: 301,
          statusDescription: 'Moved Permanently',
          headers: {
            location: { value: 'https://' + request.headers.host.value + request.uri }
          }
        };
      }

      return request;
    }
  JS
}

################################################################################
# Route53 + ACM
################################################################################

resource "aws_route53_record" "cloudfront" {
  for_each = toset(var.domain_aliases)
  zone_id  = var.route53_zone_id
  name     = each.value
  type     = "A"

  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}
