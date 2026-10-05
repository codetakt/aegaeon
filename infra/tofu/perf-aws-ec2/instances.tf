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

  user_data_base64 = local.server_user_data_base64

  lifecycle {
    precondition {
      condition     = local.server_user_data_bytes <= 16384
      error_message = "Server EC2 gzip user data must be at most 16384 bytes."
    }
  }

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

  user_data_base64 = local.loadgen_user_data_base64

  lifecycle {
    precondition {
      condition     = local.loadgen_user_data_bytes <= 16384
      error_message = "Loadgen EC2 gzip user data must be at most 16384 bytes."
    }
  }

  tags = {
    Name        = "${var.name_prefix}-loadgen"
    AegaeonRole = "loadgen"
  }

  depends_on = [aws_instance.server]
}
