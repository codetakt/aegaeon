resource "aws_kms_key" "oidc_signing" {
  count = var.create_oidc_kms_key ? 1 : 0

  description              = "${var.name_prefix} hosted OIDC RS256 signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
  deletion_window_in_days  = var.oidc_kms_deletion_window_days

  tags = {
    Name = "${var.name_prefix}-oidc-signing"
  }
}

resource "aws_kms_alias" "oidc_signing" {
  count = var.create_oidc_kms_key ? 1 : 0

  name          = "alias/${var.name_prefix}-oidc-signing"
  target_key_id = aws_kms_key.oidc_signing[0].key_id
}
