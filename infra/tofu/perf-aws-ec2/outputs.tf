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
  description = "Canonical HTTPS issuer target used by the load generator."
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

output "loadgen_image" {
  description = "Pinned artifact used by the deployed load generator."
  value       = var.loadgen_image
}
output "loadgen_entrypoint" {
  description = "Explicit executable in the pinned load-generator artifact."
  value       = var.loadgen_entrypoint
}

output "loadgen_artifact" {
  description = "Nonsecret protected host build receipt/complete source manifest locations and independently adopted digests; externally supplied, never retrieved by Terraform."
  value = {
    receipt_path           = var.loadgen_artifact_receipt_path
    receipt_sha256         = var.loadgen_artifact_receipt_sha256
    source_manifest_path   = var.loadgen_source_manifest_path
    source_manifest_sha256 = var.loadgen_source_manifest_sha256
    executable_sha256      = var.loadgen_executable_sha256
  }
}
