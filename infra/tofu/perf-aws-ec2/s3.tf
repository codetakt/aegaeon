resource "random_id" "artifact_bucket" {
  byte_length = 4
}

resource "aws_s3_bucket" "artifacts" {
  count  = var.artifact_bucket_name == null ? 1 : 0
  bucket = "${var.name_prefix}-${random_id.artifact_bucket.hex}"

  force_destroy = var.artifact_bucket_force_destroy
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  count  = var.artifact_bucket_name == null ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  count  = var.artifact_bucket_name == null ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  count  = var.artifact_bucket_name == null ? 1 : 0
  bucket = aws_s3_bucket.artifacts[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

