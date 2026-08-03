resource "aws_acm_certificate" "public" {
  count = local.managed_certificate_enabled ? 1 : 0

  domain_name       = local.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.name_prefix}-public"
  }
}

resource "aws_route53_record" "certificate_validation" {
  for_each = local.managed_certificate_enabled ? {
    for option in aws_acm_certificate.public[0].domain_validation_options :
    option.domain_name => {
      name  = option.resource_record_name
      type  = option.resource_record_type
      value = option.resource_record_value
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.value]
  ttl             = 60
  type            = each.value.type
  zone_id         = local.hosted_zone_id
}

resource "aws_acm_certificate_validation" "public" {
  count = local.managed_certificate_enabled ? 1 : 0

  certificate_arn         = aws_acm_certificate.public[0].arn
  validation_record_fqdns = [for record in aws_route53_record.certificate_validation : record.fqdn]
}
