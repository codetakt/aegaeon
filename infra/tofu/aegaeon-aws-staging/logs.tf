resource "aws_cloudwatch_log_group" "server" {
  name              = "/aegaeon/${var.name_prefix}/server"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "migrate" {
  name              = "/aegaeon/${var.name_prefix}/migrate"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "bootstrap" {
  name              = "/aegaeon/${var.name_prefix}/hosted-bootstrap"
  retention_in_days = var.log_retention_days
}
