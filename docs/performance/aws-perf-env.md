# AWS performance environment (OpenTofu / EC2)

Last updated: 2026-07-08

Status: snapshot

Owner: Performance

Audience: performance reviewers, maintainers

> **Status note (2026-07-08):** Point-in-time performance baseline; rerun the documented command before using numbers for a new release decision.

This document describes the recommended approach for collecting **low-noise**
performance baselines on AWS using OpenTofu.

GitHub-hosted CI runners are great for regression detection, but they are not a stable source of
absolute performance numbers (noisy neighbors, throttling, variable CPU allocation). For
baseline work, prefer **dedicated EC2 instances**.

## Infrastructure

The reference OpenTofu module lives at:

- `infra/tofu/perf-aws-ec2/`

It provisions two EC2 nodes in the same subnet:

- **Server** (`systemd` + Docker): runs the Aegaeon server container.
- **Load generator** (`systemd` one-shot): runs `aegaeon-loadtest` against the server and uploads a
  JSON report to S3.

SSM is used for instance access and orchestration; SSH ingress is not required.

## What to record for a baseline

At minimum, store the following per run:

- Commit SHA / image tag or digest
- Instance types (server + loadgen)
- Region / AZ / subnet
- Load test parameters (scenario, workers, RPS, duration, warmup)
- Load test report JSON (`report.json`)

Recommended additions:

- Host metrics (CPU, memory, network) for both nodes via CloudWatch Agent or node_exporter
- Server logs (structured JSON logs)

## Workflow (recommended)

1. Provision: `tofu apply` in `infra/tofu/perf-aws-ec2/`
   - For a fully standalone environment (dedicated VPC + subnet): `tofu apply -var create_vpc=true`
2. Trigger load test via SSM:
   - `sudo systemctl start aegaeon-loadtest`
3. Collect:
   - S3 report object (and optional host/server metrics)
4. Repeat:
   - Run N times and use median/p95 of medians (avoid single-run conclusions)
5. Tear down:
   - `tofu destroy` (decide whether to keep the S3 bucket with historical reports)

## Private container images

If the image registry is private (GHCR during pre-release development), configure registry auth as
described in:

- `infra/tofu/perf-aws-ec2/README.md`

## Troubleshooting

If `aegaeon-server.service` is missing on the instance (or `/etc/aegaeon` was never created),
start with the cloud-init logs and the module troubleshooting section:

- `infra/tofu/perf-aws-ec2/README.md`
