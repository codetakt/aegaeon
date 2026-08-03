# Aegaeon AWS Hosted Staging

This OpenTofu stack provisions an ephemeral hosted-staging environment for
enterprise / hosted readiness evidence.

It is intentionally separate from the KMS parity stack. The KMS/HSM claim
evidence lives under `docs/releases/evidence/kms-hsm-classifications/`; this stack is
for deployment, runtime-state, database, observability, and hosted smoke
evidence.

## Resources

- VPC with public and private subnets
- optional NAT gateway for private ECS task egress
- optional per-AZ NAT gateway mode for enterprise evidence
- optional reuse of an existing VPC and subnet set
- public ALB with HTTP and optional HTTPS listener
- optional Route53 public hosted zone lookup by zone name
- optional ACM public certificate with Route53 DNS validation
- AWS WAFv2 baseline web ACL for the ALB
- ECS Fargate cluster, service, one-off migration task definition, and
  one-off hosted bootstrap task definition
- RDS PostgreSQL with encrypted storage
- ElastiCache Redis with encryption in transit and auth token
- AWS KMS RSA signing key for hosted OIDC ID Token signing
- optional ECR repositories for the runtime and migration images
- Secrets Manager entries for:
  - `AEGAEON_DATABASE_URL`
  - shared Redis URL
  - `AEGAEON_KEY_ENCRYPTION_KEY`
  - management bootstrap token
  - initial hosted owner password
- CloudWatch log groups

## Recommended Apply Sequence

The stack can create the ECR repositories used by the ECS tasks. Apply those
repositories first, push images, then apply the full hosted staging stack.

```bash
export AWS_PROFILE=aegaeon-validation
export AWS_REGION=ap-northeast-1
export IMAGE_TAG="$(git rev-parse --short HEAD)-$(date -u +%Y%m%d%H%M%S)"

tofu -chdir=infra/tofu/aegaeon-aws-staging init

tofu -chdir=infra/tofu/aegaeon-aws-staging apply \
  -target='aws_ecr_repository.image["server"]' \
  -target='aws_ecr_repository.image["migrate"]' \
  -var "image_tag=${IMAGE_TAG}"

SERVER_REPO="$(
  tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw server_ecr_repository_url
)"
MIGRATION_REPO="$(
  tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw migration_ecr_repository_url
)"

aws ecr get-login-password --region "${AWS_REGION}" \
  | docker login --username AWS --password-stdin \
    "$(aws sts get-caller-identity --query Account --output text).dkr.ecr.${AWS_REGION}.amazonaws.com"

docker build --platform linux/amd64 --target runtime \
  --build-arg CARGO_FEATURES=kms-aws \
  -t "${SERVER_REPO}:${IMAGE_TAG}" .
docker build --platform linux/amd64 --target migrate \
  -t "${MIGRATION_REPO}:${IMAGE_TAG}" .
docker push "${SERVER_REPO}:${IMAGE_TAG}"
docker push "${MIGRATION_REPO}:${IMAGE_TAG}"
```

If using an external registry instead of managed ECR, set
`create_ecr_repositories=false` and provide both images:

```bash
tofu -chdir=infra/tofu/aegaeon-aws-staging apply \
  -var 'create_ecr_repositories=false' \
  -var 'server_image=<runtime-image>' \
  -var 'migration_image=<migration-image>'
```

If the AWS account cannot create another VPC, provide existing subnet IDs:

```bash
tofu -chdir=infra/tofu/aegaeon-aws-staging apply \
  -var "image_tag=${IMAGE_TAG}" \
  -var 'create_vpc=false' \
  -var 'vpc_id=<vpc-id>' \
  -var 'public_subnet_ids=["<public-a>","<public-b>"]' \
  -var 'private_subnet_ids=["<private-a>","<private-b>"]' \
  -var 'trusted_proxy_cidr=<vpc-cidr>'
```

The existing private subnets must have egress to ECR, CloudWatch Logs, Secrets
Manager, and the public internet through NAT or equivalent VPC endpoints. For
temporary HTTP-only wiring tests in a default VPC, you can use public subnets as
the ECS subnet set and set `assign_public_ip=true`; do not treat that as
enterprise/hosted readiness evidence.

For enterprise/hosted readiness evidence in the validation account, use the
delegated `validation.aegaeon.systems` public hosted zone and start in the
`bootstrap` phase. This creates the service with desired count zero so the
server does not fail-loop before migrations and management runtime bootstrap
complete.

```bash
tofu -chdir=infra/tofu/aegaeon-aws-staging apply \
  -var "image_tag=${IMAGE_TAG}" \
  -var 'deployment_profile=enterprise' \
  -var 'deployment_phase=bootstrap' \
  -var 'nat_gateway_mode=per_az' \
  -var 'log_retention_days=90' \
  -var 'domain_name=issuer.validation.aegaeon.systems' \
  -var 'hosted_zone_name=validation.aegaeon.systems' \
  -var 'base_url=https://issuer.validation.aegaeon.systems'
```

When `certificate_arn` is omitted, the stack creates an ACM public certificate
and the required DNS validation record in the selected hosted zone. If an
operator already issued a certificate, set `certificate_arn` to reuse it. The
managed certificate path requires public DNS resolution for
`validation.aegaeon.systems`; if the parent domain is under registrar or
registry hold, ACM validation will not complete even though the Route53 hosted
zone and records exist.

The `enterprise` profile intentionally fails closed unless HTTPS, Route53,
dedicated VPC, private ECS tasks, per-AZ NAT, WAF, Multi-AZ DB, and at least
90-day log retention are configured. Accounts that have no public hosted zone,
no issued ACM certificate, or no VPC quota can still run `deployment_profile=smoke`
for wiring tests, but those runs are not claim-quality evidence.

Without `certificate_arn` or a managed certificate, the stack exposes HTTP on
the ALB DNS name while still bootstrapping the Environment issuer URL as
`https://...` and passing only `AEGAEON_RUNTIME_ISSUER_HOST` to the server.
This is useful for `/health` wiring tests but is not sufficient for
enterprise/hosted readiness wording.

## Migration

After the bootstrap-phase apply, run the Atlas migration task:

```bash
CLUSTER="$(tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw ecs_cluster_name)"
TASK_DEF="$(tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw migration_task_definition_arn)"
SUBNETS="$(
  tofu -chdir=infra/tofu/aegaeon-aws-staging output -json private_subnet_ids \
    | jq -r 'join(",")'
)"
SG="$(tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw ecs_security_group_id)"

aws ecs run-task \
  --cluster "${CLUSTER}" \
  --launch-type FARGATE \
  --task-definition "${TASK_DEF}" \
  --network-configuration \
    "awsvpcConfiguration={subnets=[${SUBNETS}],securityGroups=[${SG}],assignPublicIp=DISABLED}"
```

Wait for the migration task to stop and verify container exit code `0`.

## Hosted Bootstrap

Run the hosted bootstrap task after migrations. It creates the first management
owner, team, tenant, ACTIVE Environment matching `base_url`, ACTIVE
configuration version, and ACTIVE `awsKms` `OIDC_ID_TOKEN_SIGNING` runtime key.

```bash
BOOTSTRAP_TASK_DEF="$(
  tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw hosted_bootstrap_task_definition_arn
)"

aws ecs run-task \
  --cluster "${CLUSTER}" \
  --launch-type FARGATE \
  --task-definition "${BOOTSTRAP_TASK_DEF}" \
  --network-configuration \
    "awsvpcConfiguration={subnets=[${SUBNETS}],securityGroups=[${SG}],assignPublicIp=DISABLED}"
```

Wait for the bootstrap task to stop and verify container exit code `0`. Re-running
the task is idempotent only after the same issuer has been fully initialized; it
fails closed if unrelated administrators already exist.

After bootstrap, move to the serving phase:

```bash
tofu -chdir=infra/tofu/aegaeon-aws-staging apply \
  -var "image_tag=${IMAGE_TAG}" \
  -var 'deployment_profile=enterprise' \
  -var 'deployment_phase=serve' \
  -var 'desired_count=2' \
  -var 'nat_gateway_mode=per_az' \
  -var 'log_retention_days=90' \
  -var 'domain_name=issuer.validation.aegaeon.systems' \
  -var 'hosted_zone_name=validation.aegaeon.systems' \
  -var 'base_url=https://issuer.validation.aegaeon.systems'
```

## Smoke Evidence

Minimum hosted smoke checks:

```bash
PUBLIC_URL="$(tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw base_url)"
curl -fsS "${PUBLIC_URL}/health"
curl -fsS "${PUBLIC_URL}/.well-known/openid-configuration"
curl -fsS "${PUBLIC_URL}/.well-known/jwks.json"
curl -fsS "${PUBLIC_URL}/api/v1/system/health"

# This stack sets AEGAEON_EXPOSE_METRICS_ON_MAIN=1. If an operator overrides
# that setting, skip this probe or query the dedicated metrics surface instead.
curl -fsS "${PUBLIC_URL}/metrics" | head
```

For `deployment_profile=smoke`, use the ALB HTTP URL only for temporary
`/health` wiring tests. Do not archive smoke-only runs as hosted readiness
evidence.

The server intentionally uses PostgreSQL-backed management runtime authority;
OIDC runtime policy and signing material are not startup environment variables
in the supported deployment path.

Retrieve the bootstrap token only when needed:

```bash
aws secretsmanager get-secret-value \
  --secret-id "$(
    tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw bootstrap_token_secret_arn
  )" \
  --query SecretString \
  --output text
```

Retrieve the initial hosted owner password only through Secrets Manager and
rotate it after the first interactive login:

```bash
aws secretsmanager get-secret-value \
  --secret-id "$(
    tofu -chdir=infra/tofu/aegaeon-aws-staging output -raw bootstrap_owner_password_secret_arn
  )" \
  --query SecretString \
  --output text
```

## Cleanup

This stack is intended to be ephemeral:

```bash
tofu -chdir=infra/tofu/aegaeon-aws-staging destroy
```

The generated OpenTofu state contains sensitive staging secrets. Keep it local,
encrypt it if archived, and do not commit it.
