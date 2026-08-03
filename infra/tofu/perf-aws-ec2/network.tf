data "aws_vpc" "default" {
  count   = var.subnet_id == null && !var.create_vpc ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.subnet_id == null && !var.create_vpc ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
}

data "aws_subnet" "default_selected" {
  count = var.subnet_id == null && !var.create_vpc ? 1 : 0
  id    = sort(data.aws_subnets.default[0].ids)[0]
}

data "aws_subnet" "provided" {
  count = var.subnet_id != null ? 1 : 0
  id    = var.subnet_id
}

resource "aws_security_group" "loadgen" {
  name        = "${var.name_prefix}-loadgen"
  description = "Aegaeon load generator"
  vpc_id      = local.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "server" {
  name        = "${var.name_prefix}-server"
  description = "Aegaeon server"
  vpc_id      = local.vpc_id

  ingress {
    from_port       = var.server_port
    to_port         = var.server_port
    protocol        = "tcp"
    security_groups = [aws_security_group.loadgen.id]
    description     = "Load generator to server"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
