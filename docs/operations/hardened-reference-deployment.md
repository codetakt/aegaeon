# Hardened Reference Deployment Guide

Last updated: 2026-05-19

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This guide records the minimum deployment-hardening baseline required before
Aegaeon can use enterprise-ready wording. It is an operator checklist, not a
formal verification claim expansion.

## Scope

This guide covers the reference production posture for:

- the OIDC/OAuth issuer server
- management API and admin-console access path
- PostgreSQL persistence
- signing-key custody
- monitoring, alerting, backup, restore, upgrade, rollback, and retention

The admin console remains a control-plane SPA. End-user credentials remain on
server-handled issuer/auth surfaces such as `/auth/*`.

## Required Deployment Shape

### Network and TLS

- Terminate public TLS at a managed load balancer, reverse proxy, or ingress
  with modern TLS policy and automatic certificate renewal.
- Expose only the required public issuer and management origins.
- Keep management origins on an allowlist through
  `aegaeon.control_plane_policies.management_allowed_origins`.
- Keep management traffic behind TLS. Management cookies are always `Secure`, and the legacy
  `AEGAEON_MANAGEMENT_COOKIE_SECURE` override is rejected if present.
- Preserve exact public issuer URL consistency across discovery, redirects,
  JWKS, and conformance runs.

### Database and Persistence

- Configure `AEGAEON_DATABASE_URL`; PostgreSQL is required and `DATABASE_URL` is not a server
  runtime fallback.
  Do not set `AEGAEON_DB_ENABLED`; the legacy database-mode toggle is rejected
  even when set to `1`/`true`.
- Use a managed PostgreSQL instance or an equivalent HA deployment with:
  - encrypted storage
  - point-in-time recovery
  - regular backup restore tests
  - migration rollback procedure
  - restricted network access
- Treat PAR `request_uri`, authorization codes, refresh-token rotation state,
  replay stores, sessions, activation tokens, and reset tokens as transactional
  state that must preserve single-use semantics.
- Before schema changes, run migrations against a staging copy and record the
  rollback decision.

### Secrets and Key Custody

- Store signing keys, client secrets, database credentials, and provider
  credentials in a secret manager. Do not commit or bake them into images.
- Use KMS/HSM-backed OIDC signing where required by the deployment profile.
- Classify each KMS/HSM deployment as claim-preserving or compat-only according
  to `docs/operations/oidc-kms-signing.md`.
- Maintain JWKS overlap and rollback windows during signing-key rotation.
- Rotate bootstrap and break-glass credentials after initial setup.

### Management Plane

- Keep management authentication server-owned.
- Keep admin-console access behind the management-session boundary.
- Require step-up or out-of-band approval for destructive or downgrade-prone
  actions in regulated environments.
- Audit every management mutation and keep audit export procedures documented.
- Review RBAC assignments and operator access on a fixed cadence.

### Federation and Local IAM

- For upstream IdP brokering, require explicit account-link remediation when
  relinking stored upstream refresh tokens or low-confidence identities.
- Keep local end-user credential submission on server-handled issuer/auth
  routes, not inside the admin SPA.
- Preserve fail-closed behaviour for stale or missing upstream federation
  diagnostics where the operator has configured strict policy.

### Observability and Alerting

- Deploy the metrics endpoint and sample alerting rules from
  `docs/operations/monitoring/`.
- At minimum, alert on:
  - JWKS HTTP error rate
  - JWKS latency
  - JWKS circuit open state
  - DCR / runtime BCP policy violations
  - refresh-token rotation conflicts
  - upstream federation logout/recovery failures
  - database connection saturation
  - authentication failure spikes
- Define SLOs for issuer endpoints, token endpoint, JWKS, discovery,
  management API, and admin-console stack E2E.

### Release, Upgrade, and Rollback

- Build release artifacts through the pinned Nix toolchain.
- Archive SBOM, vulnerability scan, dependency-policy status, release evidence,
  and container/image digests.
- Run `nix flake check`, `nix build .#server`, and the security suite before
  promoting a release.
- Run database migrations in a staged rollout with backup and rollback points.
- Keep previous signing keys and previous server image available until the
  rollback window closes.

### Data Retention and Evidence

- Define retention periods for:
  - audit events
  - security-suite output
  - release evidence
  - conformance exports
  - managed-provider evidence
  - admin-console stack evidence
  - backup restore logs
- Store evidence in durable storage with integrity metadata.
- Review stale evidence before using enterprise-ready or certified wording.
- Use `docs/operations/aws-hosted-staging.md` when collecting ephemeral AWS
  hosted deployment evidence for enterprise-readiness review.

## Enterprise-Ready Activation Checklist

Enterprise-ready wording remains blocked until all of the following are true:

- [ ] publication organization rollout evidence is archived
- [ ] managed commercial-provider evidence is fresh and hosted
- [ ] KMS/HSM deployment classification is complete for target environments
- [ ] regulated-environment runbooks are linked from `docs/operations/README.md`
- [x] hardened reference deployment guidance exists in this document
- [ ] release security evidence is archived for the target release
- [ ] management and issuer SLO baselines are refreshed for the target release

## Related Documents

- `docs/operations/management-platform-regulated-environment.md`
- `docs/operations/aws-hosted-staging.md`
- `docs/operations/oidc-kms-signing.md`
- `docs/operations/monitoring/README.md`
- `docs/operations/jwks-operations.md`
- `docs/operations/oauth21-migration-runbook.md`
- `docs/security/tcb-inventory.md`
- `docs/product-positioning.md`
