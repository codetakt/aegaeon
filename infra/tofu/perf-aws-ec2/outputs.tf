output "server_instance_id" {
  description = "EC2 instance ID of the server node."
  value       = aws_instance.server.id
}

output "server_private_ip" {
  description = "Private IP of the server node."
  value       = aws_instance.server.private_ip
}

output "server_public_ip" {
  description = "Public IP of the server node (null when associate_public_ip=false)."
  value       = aws_instance.server.public_ip
}

output "loadgen_instance_id" {
  description = "EC2 instance ID of the load generator node."
  value       = aws_instance.loadgen.id
}

output "loadgen_public_ip" {
  description = "Public IP of the load generator node (null when associate_public_ip=false)."
  value       = aws_instance.loadgen.public_ip
}

output "artifact_bucket_name" {
  description = "S3 bucket name used for reports."
  value       = local.artifact_bucket_name
}

output "artifact_prefix" {
  description = "S3 key prefix used for reports."
  value       = var.artifact_prefix
}

output "server_url" {
  description = "Server URL used by the load generator (private IP)."
  value       = local.loadtest_server_url
}

output "vpc_id" {
  description = "VPC ID used by this environment."
  value       = local.vpc_id
}

output "subnet_id" {
  description = "Subnet ID used by this environment."
  value       = local.subnet_id
}

output "ssm_server_session" {
  description = "Convenience command to open an SSM session to the server."
  value       = "aws ssm start-session --target ${aws_instance.server.id}"
}

output "ssm_loadgen_session" {
  description = "Convenience command to open an SSM session to the load generator."
  value       = "aws ssm start-session --target ${aws_instance.loadgen.id}"
}
