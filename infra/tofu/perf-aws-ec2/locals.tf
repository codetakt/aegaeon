locals {
  tags = {
    "Project"   = "aegaeon"
    "Component" = "perf"
    "ManagedBy" = "opentofu"
  }

  server_trusted_proxies = trimspace(var.server_trusted_proxies)

  subnet_id = (
    var.subnet_id != null ? var.subnet_id : (
      var.create_vpc ? aws_subnet.perf_public[0].id : data.aws_subnet.default_selected[0].id
    )
  )

  vpc_id = (
    var.subnet_id != null ? data.aws_subnet.provided[0].vpc_id : (
      var.create_vpc ? aws_vpc.perf[0].id : data.aws_vpc.default[0].id
    )
  )

  artifact_bucket_name = coalesce(
    var.artifact_bucket_name,
    try(aws_s3_bucket.artifacts[0].bucket, null),
  )

  loadtest_server_url = var.issuer_url

  node_secret_arns = {
    server  = [var.server_secret_arn]
    loadgen = compact([var.client_secret_arn, var.metrics_secret_arn])
  }
  node_secret_kms_key_arns = {
    server  = var.server_secret_kms_key_arns
    loadgen = distinct(concat(var.client_secret_kms_key_arns, var.metrics_secret_kms_key_arns))
  }
}
