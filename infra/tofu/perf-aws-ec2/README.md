# AWS performance environment (OpenTofu / EC2 + systemd + SSM)

This OpenTofu module provisions a minimal **two-node** performance test environment on AWS:

- **Server**: runs the Aegaeon server as a `systemd`-managed Docker container.
- **Load generator**: runs `aegaeon-loadtest` (also from the same container image) and can upload
  JSON reports to S3.

The instances are managed via **AWS Systems Manager (SSM)**; no SSH ingress is required.

## Prerequisites

- OpenTofu installed (`tofu`)
- AWS credentials configured via the standard AWS SDK chain (you mentioned `direnv`)
  - Ensure your profile/vars include a region (`AWS_REGION` / `AWS_DEFAULT_REGION`)
- AWS SSM Session Manager Plugin (for `aws ssm start-session`)
- Docker image accessible from the EC2 instances (default uses `ghcr.io/...:latest`)

## Private GHCR images (recommended auth wiring)

If your `server_image` points at a **private** GHCR image, the instances must authenticate before
`docker pull` can succeed.

Per GitHub Docs ("Working with the Container registry"), GitHub Packages registry authentication
for GHCR uses a **personal access token (classic)** (fine-grained PATs are not supported for
`docker login`).

This module intentionally does **not** accept a GHCR token as a Terraform variable, because that
would write the token into `terraform.tfstate`.

Instead, store the token in **SSM Parameter Store** or **Secrets Manager**, and provide only the
parameter/secret identifier to this module (non-secret).

### Option A: SSM Parameter Store (SecureString)

Create the parameter manually (outside OpenTofu):

```bash
read -s GHCR_TOKEN
aws ssm put-parameter \
  --name /aegaeon/perf/ghcr_token \
  --type SecureString \
  --value "$GHCR_TOKEN" \
  --overwrite
unset GHCR_TOKEN
```

Then apply with:

```bash
tofu apply \
  -var 'ghcr_username=<your-github-username>' \
  -var 'ghcr_token_ssm_parameter_name=/aegaeon/perf/ghcr_token'
```

### Option B: AWS Secrets Manager

Create the secret manually (outside OpenTofu):

```bash
read -s GHCR_TOKEN
aws secretsmanager create-secret \
  --name aegaeon/perf/ghcr_token \
  --secret-string "$GHCR_TOKEN" \
  --description "GHCR token for aegaeon perf env"
unset GHCR_TOKEN
```

Then apply with:

```bash
tofu apply \
  -var 'ghcr_username=<your-github-username>' \
  -var 'ghcr_token_secretsmanager_secret_id=aegaeon/perf/ghcr_token'
```

Notes:

- Create a classic PAT with the `read:packages` scope (download container images + metadata). Your
  user account must also have read access to the package/repository.
- If your organization enforces SSO, you must authorize/enable SSO for the new token.
- Docker credentials are stored under `/run/` (tmpfs) via `DOCKER_CONFIG` and are cleared on reboot.
- After you create/update the token, restart the server service:
  - `sudo systemctl restart aegaeon-server`

## Quick start

```bash
cd infra/tofu/perf-aws-ec2
tofu init
tofu apply
```

### Standalone apply (dedicated VPC)

To provision a fully independent environment (including VPC/subnet), set:

```bash
tofu apply -var create_vpc=true
```

After apply:

- The server instance will start the service automatically (`aegaeon-server.service`).
- The load generator instance will have a one-shot service installed (`aegaeon-loadtest.service`)
  that you can trigger on demand.

## Network selection

This module supports three modes:

1. `create_vpc=true`: create a dedicated VPC + public subnet (standalone apply).
2. `subnet_id=<id>`: use an existing subnet (and its VPC).
3. Default: use the **default VPC** and pick the first subnet.

If your subnet does not provide egress (no public IP + no NAT + no VPC endpoints), package install
and container pulls will fail. In that case either:

- set `associate_public_ip=true`, or
- run in a VPC with NAT / the required endpoints (recommended for more controlled environments).

## Troubleshooting

### `aegaeon-server.service` is missing (or `/etc/aegaeon` does not exist)

This usually means the EC2 **user data** script failed early (cloud-init), so the systemd unit
and config files were never written.

Confirm you are on the intended node:

- Server: `tofu output -raw ssm_server_session`
- Loadgen: `tofu output -raw ssm_loadgen_session`

On the instance, inspect:

- `sudo tail -n 200 /var/log/cloud-init-output.log`
- `sudo journalctl -u cloud-final -b --no-pager | tail -n 200`
- `sudo cat /var/log/aegaeon-user-data.log || true`

Common causes:

- **No internet egress** (no public IP + no NAT + no VPC endpoints). Verify `associate_public_ip`
  and check `tofu output -raw server_public_ip`.
- The instance was created before user data changes. User data updates do not re-run on an
  existing instance; replace the nodes:
  - `tofu apply -replace=aws_instance.server -replace=aws_instance.loadgen`

## Run a load test

Option A: start the load test via SSM:

```bash
aws ssm send-command \
  --document-name AWS-RunShellScript \
  --targets "Key=InstanceIds,Values=$(tofu output -raw loadgen_instance_id)" \
  --parameters commands="sudo systemctl start aegaeon-loadtest"
```

Option B: interactive SSM session:

```bash
aws ssm start-session --target "$(tofu output -raw loadgen_instance_id)"
sudo systemctl start aegaeon-loadtest
```

## Results

By default the load generator uploads JSON reports to:

`s3://$(tofu output -raw artifact_bucket_name)/$(tofu output -raw artifact_prefix)<run-id>/report.json`

If the server exposes `/metrics` on the main port (`expose_metrics_on_main=true`), the load generator
also uploads a Prometheus snapshot captured after the run:

`s3://$(tofu output -raw artifact_bucket_name)/$(tofu output -raw artifact_prefix)<run-id>/server.metrics.prom`

You can also find local files on the load generator instance under:

- `/opt/aegaeon/results/`

## Destroy

```bash
tofu destroy
```

Note: if you use an **external** artifact bucket (`artifact_bucket_name`), it will not be managed
by this module. If you let this module create the bucket, `artifact_bucket_force_destroy` controls
whether objects are deleted on destroy.
