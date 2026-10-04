data "aws_ami" "al2023_amd64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

resource "aws_instance" "server" {
  ami                    = data.aws_ami.al2023_amd64.id
  instance_type          = var.server_instance_type
  subnet_id              = local.subnet_id
  vpc_security_group_ids = [aws_security_group.server.id]

  iam_instance_profile = aws_iam_instance_profile.perf_instance["server"].name

  associate_public_ip_address = var.associate_public_ip
  user_data_replace_on_change = true

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data_base64 = base64gzip(templatefile("${path.module}/user_data_server.sh.tftpl", {
    delivery_helper                  = file("${path.module}/delivery_helper.py")
    delivery_init                    = file("${path.module}/runtime_delivery/__init__.py")
    delivery_common                  = file("${path.module}/runtime_delivery/common.py")
    delivery_credentials             = file("${path.module}/runtime_delivery/credentials.py")
    delivery_filesystem              = file("${path.module}/runtime_delivery/filesystem.py")
    delivery_artifacts               = file("${path.module}/runtime_delivery/artifacts.py")
    delivery_reports                 = file("${path.module}/runtime_delivery/reports.py")
    delivery_metrics                 = file("${path.module}/runtime_delivery/metrics.py")
    delivery_orchestration           = file("${path.module}/runtime_delivery/orchestration.py")
    aws_region                       = data.aws_region.current.id
    server_image                     = var.server_image
    server_entrypoint                = var.server_entrypoint
    issuer_host                      = var.issuer_host
    issuer_url                       = var.issuer_url
    server_secret_arn                = var.server_secret_arn
    server_secret_version            = var.server_secret_version
    server_port                      = var.server_port
    trusted_proxies                  = local.server_trusted_proxies
    ghcr_auth_enabled                = var.ghcr_auth_enabled
    ghcr_username                    = var.ghcr_username == null ? "" : var.ghcr_username
    ghcr_token_ssm_parameter_name    = var.ghcr_token_ssm_parameter_name == null ? "" : var.ghcr_token_ssm_parameter_name
    ghcr_token_secretsmanager_secret = var.ghcr_token_secretsmanager_secret_id == null ? "" : var.ghcr_token_secretsmanager_secret_id
  }))

  tags = {
    Name        = "${var.name_prefix}-server"
    AegaeonRole = "server"
  }
}

resource "aws_instance" "loadgen" {
  ami                    = data.aws_ami.al2023_amd64.id
  instance_type          = var.loadgen_instance_type
  subnet_id              = local.subnet_id
  vpc_security_group_ids = [aws_security_group.loadgen.id]

  iam_instance_profile = aws_iam_instance_profile.perf_instance["loadgen"].name

  associate_public_ip_address = var.associate_public_ip
  user_data_replace_on_change = true

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data_base64 = base64gzip(templatefile("${path.module}/user_data_loadgen.sh.tftpl", {
    delivery_helper                  = file("${path.module}/delivery_helper.py")
    delivery_init                    = file("${path.module}/runtime_delivery/__init__.py")
    delivery_common                  = file("${path.module}/runtime_delivery/common.py")
    delivery_credentials             = file("${path.module}/runtime_delivery/credentials.py")
    delivery_filesystem              = file("${path.module}/runtime_delivery/filesystem.py")
    delivery_artifacts               = file("${path.module}/runtime_delivery/artifacts.py")
    delivery_reports                 = file("${path.module}/runtime_delivery/reports.py")
    delivery_metrics                 = file("${path.module}/runtime_delivery/metrics.py")
    delivery_orchestration           = file("${path.module}/runtime_delivery/orchestration.py")
    aws_region                       = data.aws_region.current.id
    server_image                     = var.loadgen_image
    loadgen_entrypoint               = var.loadgen_entrypoint
    loadgen_artifact_receipt_path    = var.loadgen_artifact_receipt_path
    loadgen_artifact_receipt_sha256  = var.loadgen_artifact_receipt_sha256
    loadgen_source_manifest_path     = var.loadgen_source_manifest_path
    loadgen_source_manifest_sha256   = var.loadgen_source_manifest_sha256
    loadgen_executable_sha256        = var.loadgen_executable_sha256
    issuer_url                       = var.issuer_url
    client_secret_arn                = var.client_secret_arn
    client_secret_version            = var.client_secret_version
    metrics_secret_arn               = var.metrics_secret_arn
    metrics_secret_version           = var.metrics_secret_version
    server_url                       = local.loadtest_server_url
    artifact_bucket                  = local.artifact_bucket_name
    artifact_prefix                  = var.artifact_prefix
    auto_run_loadtest                = var.auto_run_loadtest
    workers                          = var.loadtest_workers
    rps                              = var.loadtest_rps
    run_time                         = var.loadtest_run_time
    warmup                           = var.loadtest_warmup
    scenario                         = var.loadtest_scenario
    ghcr_auth_enabled                = var.ghcr_auth_enabled
    ghcr_username                    = var.ghcr_username == null ? "" : var.ghcr_username
    ghcr_token_ssm_parameter_name    = var.ghcr_token_ssm_parameter_name == null ? "" : var.ghcr_token_ssm_parameter_name
    ghcr_token_secretsmanager_secret = var.ghcr_token_secretsmanager_secret_id == null ? "" : var.ghcr_token_secretsmanager_secret_id
  }))

  tags = {
    Name        = "${var.name_prefix}-loadgen"
    AegaeonRole = "loadgen"
  }

  depends_on = [aws_instance.server]
}
