# OIDF Conformance (Docker + nginx + Let's Encrypt DNS-01)

This directory contains helper scripts and a Docker Compose template to run the OpenID Foundation conformance-suite behind an HTTPS reverse proxy, together with `aegaeon-server`.

## Why this exists

Recent upstream suite plans for OP/AS enforce **HTTPS** URLs (e.g., discovery URL must be `https://...` and all `*_endpoint` fields must use `https`). A simple `X-Forwarded-Proto` header is not sufficient for OP test plans because the suite validates URL strings and performs HTTPS calls.

This stack provides:

- `nginx` TLS termination (single wildcard / SAN cert)
- `aegaeon-server` behind the proxy (HTTP internally, HTTPS externally)
- conformance-suite behind the proxy (HTTP internally, HTTPS externally)
- MongoDB for the suite
- optional ACME issuance via DNS-01 using `lego`

It also assigns Docker network aliases so that `${AEGAEON_DOMAIN}` / `${SUITE_DOMAIN}` resolve to the `nginx` container from within the stack (useful if your public DNS points at `127.0.0.1`).

## Local self-signed TLS quick start

For local development, use the reserved `.localhost` zone and a self-signed local CA. This avoids ACME and public DNS while still exercising the real HTTPS path end-to-end.

1) Create a local env file:

```bash
cp scripts/oidf_conformance/.env.local.example scripts/oidf_conformance/.env.local
```

2) Generate the local CA and SAN certificate:

```bash
OIDF_ENV_FILE=scripts/oidf_conformance/.env.local \
  scripts/oidf_conformance/prepare_local_tls.sh
```

3) Bring the stack up:

```bash
OIDF_ENV_FILE=scripts/oidf_conformance/.env.local \
  scripts/oidf_conformance/run_local_tls_stack.sh
```

Defaults:

- `AEGAEON_PUBLIC_BASE_URL=https://aegaeon.localhost:28443`
- `AEGAEON_RUNTIME_ISSUER_HOST=aegaeon.localhost:28443`
- `SUITE_PUBLIC_BASE_URL=https://suite.localhost:28443`
- `NGINX_HTTP_PORT=28080`
- `NGINX_HTTPS_PORT=28443`

Host-side health checks:

```bash
curl --cacert scripts/oidf_conformance/certificates/oidf-local-ca.crt \
  https://aegaeon.localhost:28443/health

curl --cacert scripts/oidf_conformance/certificates/oidf-local-ca.crt \
  https://suite.localhost:28443/actuator/health
```

The local CA is also imported into the suite JVM automatically, so the suite can call both HTTPS origins without disabling certificate validation.

## Quick start

1) Copy the env template:

```bash
cp scripts/oidf_conformance/.env.example scripts/oidf_conformance/.env
```text

Edit `scripts/oidf_conformance/.env`:
- Set `AEGAEON_DOMAIN`, `SUITE_DOMAIN`
- Set `AEGAEON_PUBLIC_BASE_URL`, `AEGAEON_RUNTIME_ISSUER_HOST`, and `SUITE_PUBLIC_BASE_URL`
- Set `CERT_PRIMARY_DOMAIN` (certificate file name under `/etc/letsencrypt/certificates/`)
- Set `LEGO_EMAIL`, `LEGO_DNS=route53`, plus your Route53 credentials (below)

2) Obtain a certificate (DNS-01) into the named volume (recommended):

```bash
docker compose -f scripts/oidf_conformance/docker-compose.oidf.yml --env-file scripts/oidf_conformance/.env --profile acme run --rm acme
```

Alternative: if you already have a certificate locally (e.g. you placed
`${CERT_PRIMARY_DOMAIN}.crt` / `.key` under `scripts/oidf_conformance/certificates/`), you can skip ACME and
mount the directory:

> Note: for a wildcard/SAN cert keyed by the base zone (e.g. `codetakt.dev.crt`), set
> `CERT_PRIMARY_DOMAIN=codetakt.dev` even if `AEGAEON_DOMAIN` is `aegaeon.codetakt.dev`.

```bash
docker compose \
  -f scripts/oidf_conformance/docker-compose.oidf.yml \
  -f scripts/oidf_conformance/docker-compose.localcert.yml \
  --env-file scripts/oidf_conformance/.env up -d
```

1) Build/load the local Aegaeon image (Nix):

```bash
nix run .#docker-build
```

If you prefer to use a pre-built image, set `AEGAEON_IMAGE` in `scripts/oidf_conformance/.env` (for example,
`AEGAEON_IMAGE=ghcr.io/<OWNER>/<REPO>/aegaeon-server:latest`) and skip the local build step.

1) Bring the stack up:

```bash
docker compose -f scripts/oidf_conformance/docker-compose.oidf.yml --env-file scripts/oidf_conformance/.env up -d
```

1) Open:

- Suite UI: `${SUITE_PUBLIC_BASE_URL}`
- Aegaeon discovery (OIDC): `${AEGAEON_PUBLIC_BASE_URL}/.well-known/openid-configuration`

## Runtime configuration

Aegaeon requires PostgreSQL and loads protocol policy from the active management configuration for
`AEGAEON_RUNTIME_ISSUER_HOST`. `AEGAEON_PUBLIC_BASE_URL` remains the externally reachable URL used
by the suite. Before starting the Aegaeon service in this stack:

1. Apply the database migrations to the compose `postgres` service.
2. Create an active management environment whose issuer host matches
   `AEGAEON_RUNTIME_ISSUER_HOST` and whose public issuer URL matches `AEGAEON_PUBLIC_BASE_URL`.
3. Enable OIDC discovery/userinfo and any conformance-specific Bearer-token policy in that
   management policy document.
4. Store the RS256 ID Token signing key as an active `OIDC_ID_TOKEN_SIGNING` runtime key.

Do not enable OIDC, set signing key material, or relax sender-constrained-token policy with
`AEGAEON_*` startup environment variables; those legacy startup controls are intentionally rejected.

For local headless smoke runs, `run_oauth2_suite.sh` expects a PostgreSQL-backed
runtime authority before starting the server:

- `AEGAEON_DATABASE_URL` is required.
- `AEGAEON_RUNTIME_ISSUER_HOST` or `OIDF_RUNTIME_ISSUER_HOST` is required.
- `OIDF_APPLY_DATABASE_MIGRATIONS=1` applies Atlas migrations to a fresh local database.

The database must already contain a suitable active management environment,
runtime policy, clients, and runtime key set for the selected issuer host. Use
the management API or hosted bootstrap flow to create that runtime authority.

## Suggested starting planName

Given the current Aegaeon implementation posture, the lowest-friction OP plan to start with is:

- `oidcc-config-certification-test-plan`

It primarily verifies discovery + JWKS requirements and is a good first step to produce machine-readable exports before tackling larger OIDC/FAPI plans.

For OIDC basic plans, configure the active management policy for classic Bearer token behaviour when
the Suite plan requires it. That policy lives in PostgreSQL, not in process environment variables.

## Automated (headless) run with exports

If you want a reproducible, machine-readable export on every run, use:

```bash
./scripts/oidf_conformance/run_oidcc_basic_plan.sh
```

Key environment variables:

- `OIDF_PLAN_NAME` (default: `oidcc-config-certification-test-plan`)
- `OIDF_PLAN_ALIAS` (default: `aegaeon-oidcc-basic`)
- `OIDF_ONLY_MODULES` (optional; space-separated test module names)
- `OIDF_LOCAL_CERTS=1` (default) uses `scripts/oidf_conformance/certificates/${CERT_PRIMARY_DOMAIN}.crt/.key`
- `OIDF_LOCAL_CA_CERT_FILENAME` lets host-side scripts add `--cacert` automatically when using a local CA
- `OIDF_AUTO_UPLOAD_EVIDENCE=1` (optional; default `0`) uploads evidence placeholders via the Suite Image API
- `OIDF_EVIDENCE_IMAGE_DATA_URI` (required when auto-uploading; `data:image/png;base64,...`)

Artefacts are written under:

- `artifacts/conformance/<planName>/plan-export/results.json`
- `artifacts/conformance/<planName>/plan-export/export.zip`
- `artifacts/conformance/<planName>/plan-export/plan.json`

Some plans require front-channel steps; the script attempts to auto-visit URLs reported by the suite,
and will also emulate the Suite callback page's JS submission (it posts the effective URL's fragment
to the `/test/a/<alias>/implicit/<id>` endpoint). You may still need to open the Suite UI and
proceed manually for modules that require evidence uploads (e.g., screenshot-based negative tests).

## Plan discovery

To list all test plans available in a running conformance suite:

```bash
./scripts/oidf_conformance/discover_plans.sh [SUITE_BASE_URL]
```

Defaults to `$SUITE_HTTPS_BASE` (or `https://localhost:9999`). Outputs one plan name per line, sorted alphabetically. Useful for CI bootstrap or checking which plans the current suite version supports.

## Conformance evidence archival

Evidence is archived under `artifacts/conformance/` (tracked via `.gitkeep` files):

```text
artifacts/conformance/
  .gitkeep
  bootstrap/                        # Suite bootstrap data (plan availability snapshots)
    .gitkeep
    plan_available_<RUN_ID>.json    # Raw /api/plan/available response
    plan_available_<RUN_ID>.txt     # One plan name per line
  <planName>/                       # Per-plan run artefacts (e.g. oidcc-config-certification-test-plan/)
    run.log                         # Combined stdout/stderr for the run
    run-<RUN_ID>.log                # Timestamped copy
    plan_id_<RUN_ID>.txt            # Suite-assigned plan instance ID
    suite_commit_<RUN_ID>.txt       # Suite git commit hash
    plan-export/
      results.json                  # Module-by-module results (latest)
      results_<RUN_ID>.json         # Timestamped results
      export.zip                    # Suite plan export (latest)
      export_<RUN_ID>.zip           # Timestamped export
      plan.json                     # Full plan JSON (latest)
      plan_<RUN_ID>.json            # Timestamped plan JSON
      files_<RUN_ID>/               # Unzipped export contents
      info_<testId>_<RUN_ID>.json   # Per-module /api/info snapshot
      latest_run_id.txt             # Pointer to most recent RUN_ID
      plan_id.txt                   # Pointer to most recent plan instance
      suite_commit.txt              # Suite commit for latest run
```

The `bootstrap/` directory is always populated (even when `AEG_OIDF_CONFORMANCE_ENABLED=0`) so that CI can verify which plans the suite exposes.

In CI, the entire `artifacts/conformance/` tree is uploaded as a GitHub Actions artifact named `oidf-conformance-results`.

## Route53 (DNS-01) notes

### CI credentials (recommended)

You do **not** need to store long-lived AWS access keys in CI.

Recommended options:

- **GitHub Actions**: use **OIDC → STS AssumeRole** (no `AWS_SECRET_ACCESS_KEY` stored in GitHub).
- **AWS-native CI (CodeBuild/CodePipeline)**: use the build's **IAM role** (no static keys).

For GitHub Actions, the rough flow is:

1) Create an IAM role with a trust policy for `token.actions.githubusercontent.com` (OIDC) and scope it to your repo/branch/environment.
2) Attach a least-privilege Route53 policy (below).
3) In CI, call `aws-actions/configure-aws-credentials@v4` to assume the role; it exports `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` for the step.
4) Run the `acme` profile: `docker compose ... --profile acme run --rm acme`.

### GitHub Actions (OIDC) snippets

**IAM trust policy** (scope the `sub` as tightly as you can):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:<OWNER>/<REPO>:ref:refs/heads/<BRANCH>"
        }
      }
    }
  ]
}
```

**Workflow step** (minimal example):

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>
      aws-region: us-east-1
  - run: |
      cp scripts/oidf_conformance/.env.example scripts/oidf_conformance/.env
      # edit scripts/oidf_conformance/.env (domains/base URLs) in your pipeline
      docker compose -f scripts/oidf_conformance/docker-compose.oidf.yml \
        --env-file scripts/oidf_conformance/.env --profile acme run --rm acme
```

### Required env vars

Provide these via CI environment variables or `scripts/oidf_conformance/.env`:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- (optional) `AWS_SESSION_TOKEN` (if using STS)
- `AWS_REGION=us-east-1` (safe default; Route53 is global)
- (optional) `AWS_HOSTED_ZONE_ID` (only needed if lego can't disambiguate)

### Suggested IAM policy (least privilege)

Attach a policy like the following to the IAM principal used for DNS-01. Replace `Z123...` with your hosted zone ID for `codetakt.dev`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:ListHostedZonesByName",
        "route53:ListResourceRecordSets"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:GetChange",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": [
        "arn:aws:route53:::hostedzone/Z1234567890ABC",
        "arn:aws:route53:::change/*"
      ]
    }
  ]
}
```

### Optional hardening: restrict `_acme-challenge` records only

Route 53 supports condition keys for `ChangeResourceRecordSets` so you can scope changes down to ACME TXT records only.

Example (allow only TXT `CREATE|UPSERT|DELETE` for `_acme-challenge.*.codetakt.dev`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "route53:ChangeResourceRecordSets",
      "Resource": "arn:aws:route53:::hostedzone/Z1234567890ABC",
      "Condition": {
        "ForAllValues:StringEquals": {
          "route53:ChangeResourceRecordSetsRecordTypes": ["TXT"],
          "route53:ChangeResourceRecordSetsActions": ["CREATE", "UPSERT", "DELETE"]
        },
        "ForAllValues:StringLike": {
          "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
            "_acme-challenge.codetakt.dev",
            "_acme-challenge.\\052.codetakt.dev"
          ]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "route53:GetChange",
      "Resource": "arn:aws:route53:::change/*"
    }
  ]
}
```
