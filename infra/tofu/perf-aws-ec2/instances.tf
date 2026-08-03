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

  iam_instance_profile = aws_iam_instance_profile.perf_instance.name

  associate_public_ip_address = var.associate_public_ip
  user_data_replace_on_change = true

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user_data_server.sh.tftpl", {
    aws_region                       = data.aws_region.current.id
    server_image                     = var.server_image
    server_port                      = var.server_port
    expose_metrics_on_main           = var.expose_metrics_on_main
    trusted_proxies                  = local.server_trusted_proxies
    ghcr_auth_enabled                = var.ghcr_auth_enabled
    ghcr_username                    = var.ghcr_username == null ? "" : var.ghcr_username
    ghcr_token_ssm_parameter_name    = var.ghcr_token_ssm_parameter_name == null ? "" : var.ghcr_token_ssm_parameter_name
    ghcr_token_secretsmanager_secret = var.ghcr_token_secretsmanager_secret_id == null ? "" : var.ghcr_token_secretsmanager_secret_id
  })

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

  iam_instance_profile = aws_iam_instance_profile.perf_instance.name

  associate_public_ip_address = var.associate_public_ip
  user_data_replace_on_change = true

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user_data_loadgen.sh.tftpl", {
    aws_region                       = data.aws_region.current.id
    server_image                     = var.server_image
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
  })

  tags = {
    Name        = "${var.name_prefix}-loadgen"
    AegaeonRole = "loadgen"
  }

  depends_on = [aws_instance.server]
}
