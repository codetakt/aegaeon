# AWS Hosted Staging Runbook

Last updated: 2026-06-18

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Scope

This runbook defines the ephemeral AWS hosted-staging path used to collect
enterprise / hosted readiness deployment evidence.

It does not make the public enterprise-readiness claim active by itself. The
claim gate must remain inactive until the evidence bundle is reviewed according
to `docs/releases/evidence/enterprise-readiness-evidence-bundle.md`.

## Reference Stack

The source-managed OpenTofu stack is:

- `infra/tofu/aegaeon-aws-staging/`

It provisions:

- ALB with optional ACM-backed HTTPS
- AWS WAFv2 baseline protection for the ALB
- ECS Fargate service for `aegaeon-server`
- one-off ECS task definitions for Atlas migrations and hosted bootstrap
- RDS PostgreSQL
- ElastiCache Redis for shared runtime state
- dedicated VPC/subnets, or operator-provided existing VPC/subnets
- Route53 public hosted zone lookup by name for validation DNS
- optional ACM public certificate with Route53 DNS validation
- AWS KMS RSA signing key for OIDC ID Token signing
- optional ECR repositories for the runtime and migration images
- Secrets Manager entries for database URL, Redis URL, KEK, bootstrap token,
  and initial hosted owner password
- CloudWatch log groups

The stack is intentionally separate from:

- `infra/tofu/oidc-aws-kms-parity/`, which is only for KMS/HSM parity evidence
- `infra/tofu/perf-aws-ec2/`, which is only for low-noise performance baselines

## Hosted Readiness Requirements

For enterprise / hosted readiness wording, run the stack with:

- `certificate_arn` set to an ACM certificate, or leave it unset so the stack
  manages an ACM public certificate with DNS validation
- `base_url` set to an `https://` issuer URL
- `domain_name` and either `hosted_zone_id` or `hosted_zone_name` set when
  Route53 should manage the alias
- ECS tasks using private subnets with NAT or equivalent VPC endpoints
- RDS and Redis left private to the VPC
- `deployment_profile=enterprise`
- `deployment_phase=bootstrap` for initial apply, then `deployment_phase=serve`
  after migrations and hosted bootstrap complete
- `desired_count >= 2` in the `serve` phase for multi-node shared-state
  evidence
- `create_vpc=true`, `nat_gateway_mode=per_az`, WAF enabled, and log retention
  of at least 90 days

HTTP-only ALB deployment is useful for `/health` wiring tests, but it is not
sufficient for hosted readiness evidence. The active management Environment's
issuer URL must be HTTPS, and the process must select it with
`AEGAEON_RUNTIME_ISSUER_HOST`; non-loopback HTTP issuer URLs fail closed during
runtime configuration hydration.

For the validation account, use:

- `AWS_PROFILE=aegaeon-validation`
- `domain_name=issuer.validation.aegaeon.systems`
- `hosted_zone_name=validation.aegaeon.systems`
- `base_url=https://issuer.validation.aegaeon.systems`

The validation hosted zone can be read as a Route53 data source once the
account credentials are active. Full ACM certificate validation requires public
DNS resolution for the delegated zone; if `aegaeon.systems` is under
registrar/registry hold, the Route53 records can be created but ACM validation
will remain pending.

Existing-VPC mode is supported for integration smoke tests and for operator
accounts that already provide an enterprise-equivalent network baseline. Do not
use a default VPC with public ECS task IPs as hosted readiness evidence.

## Evidence Sequence

1. Select a unique image tag for the evidence run, preferably
   `<git-sha>-<UTC timestamp>`.
2. Apply the managed ECR repository targets, unless using an external registry.
3. Build and push both Dockerfile targets:
   - `runtime` for `aegaeon-server` and `aegaeon-hosted-bootstrap`; build it
     with `--build-arg CARGO_FEATURES=kms-aws`
   - `migrate` for the Atlas migration task
4. Record image digests after push.
5. Apply `infra/tofu/aegaeon-aws-staging/` with HTTPS inputs,
   `deployment_profile=enterprise`, and `deployment_phase=bootstrap`.
6. Run the one-off migration task.
7. Run the one-off hosted bootstrap task and verify exit code `0`.
8. Re-apply with `deployment_phase=serve` and `desired_count >= 2`.
9. Wait for the ECS service to become stable.
10. Verify `GET /health` through the ALB, OIDC discovery metadata over the
    HTTPS issuer URL, the JWKS endpoint, management `/api/v1/system/health`,
    and authenticated management `/api/v1/operations/metrics`.
11. Run OIDC token-flow smoke against the hosted issuer after creating a test
    client through the management plane.
12. Archive logs, command output, image digests, ALB target health, ECS service
    status, RDS metadata, Redis metadata, and smoke-test results into the
    release evidence archive.
13. Destroy the staging stack unless the evidence review requires keeping it
    alive temporarily.

## Runtime Boundary

The supported hosted path has no configuration-authority selector. Issuer
policy, clients, DCR bearer policy, and runtime signing keys are loaded from
PostgreSQL-backed management state. Do not set `AEGAEON_CONFIG_AUTHORITY`; any
value, including the former `management-database` and `startup-environment`
tokens, is a startup error.

The hosted bootstrap task is the only supported empty-database initialization
path for this stack. It creates the first management owner and the initial
ACTIVE issuer configuration before the serving phase starts. This avoids
startup environment policy shortcuts while still letting the server fail closed
when no ACTIVE issuer configuration exists.

The stack wires one shared Redis endpoint into all required shared runtime-store
environment variables so multi-node deployments do not fall back to
process-local single-use, replay, CSRF, session, or rate-limit state.

## Image Custody

For the source-managed ECR path, keep `ecr_image_tag_mutability=IMMUTABLE` and
use a fresh image tag per run. Record:

- `tofu output -raw server_image`
- `tofu output -raw migration_image`
- `aws ecr describe-images` output for both repositories and tags
- container image digests used by the ECS task definitions

If using an external registry, set `create_ecr_repositories=false` and provide
both `server_image` and `migration_image`. Do not reuse the runtime image as the
migration image unless that image intentionally contains the Atlas binary and
migration entrypoint.

## Cleanup

Destroy the stack after evidence collection:

```bash
AWS_PROFILE=<profile> AWS_REGION=<region> \
nix develop .#default --command bash -c \
  'tofu -chdir=infra/tofu/aegaeon-aws-staging destroy'
```

The stack state contains generated staging secrets. Keep it out of git and
destroy it with the stack unless a reviewed evidence-retention procedure says
otherwise.

## Related Documents

- `docs/operations/hardened-reference-deployment.md`
- `docs/operations/runtime-configuration.md`
- `docs/releases/evidence/enterprise-readiness-evidence-bundle.md`
- `docs/performance/enterprise-slo-baselines.md`
