locals {
  tags = {
    "Project"   = "aegaeon"
    "Component" = "perf"
    "ManagedBy" = "opentofu"
  }

  default_server_trusted_proxy_cidr = (
    var.create_vpc ? var.public_subnet_cidr : (
      var.subnet_id != null ? data.aws_subnet.provided[0].cidr_block : data.aws_subnet.default_selected[0].cidr_block
    )
  )

  server_trusted_proxies = (
    var.server_trusted_proxies != null ? trimspace(var.server_trusted_proxies) : "${local.default_server_trusted_proxy_cidr},127.0.0.1/32,::1/128"
  )

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

  loadtest_server_url = "http://${aws_instance.server.private_ip}:${var.server_port}"
}
