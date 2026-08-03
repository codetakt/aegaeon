# Management Plane Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

Datastore: PostgreSQL

Resource IDs: UUIDv4

This document specifies the Phase 1 management plane for Aegaeon. It is written to be directly
translatable into OpenAPI and a Postgres schema with minimal reshaping.

## Goals

- Make the verified-first OAuth/OIDC data plane operable in production.
- Preserve a standards-first, fail-closed posture.
- Respect the current verified-vs-compat split in the data plane; do not assume that every supported runtime algorithm is already inside the formal claim boundary.
- Make all management changes auditable and rollbackable.
- Standardise on a host-based issuer model: one Environment equals exactly one issuer (domain).

## Non-goals (Phase 1)

- Replacing all JSON parsing boundaries with verified parsers.
- Admin SSO for the management plane (OIDC / SAML) (Phase 2+).
- Two-person approvals (Phase 2+).
- Full SIEM/Webhook/SCIM integrations (Phase 2+). Phase 1 provides SaaS-first S3 export.
- The original Phase 1 scope did not include full local end-user IAM / provisioning for the
  "Aegaeon as primary authority" posture. The current delivered baseline is specified in
  `../primary-authority-user-management.md`.
- The original Phase 1 scope did not include the full broker / federation operations control plane
  for the "upstream authority + downstream IdP" posture. The current delivered baseline is
  specified in `../oidc-rp-brokering-spec.md`.

## Terms & hierarchy

- **Team**: top-level management boundary (ownership, administrators, RBAC, audit scope, and
  hosted/commercial account mapping).
- **Tenant**: operational unit under a Team; participates in issuer host naming.
- **Environment**: security boundary for OIDC; owns issuer, keys, clients, policies, audit scope.
- **Issuer**: `https://{environment}.{tenant}.{your-domain}` (Phase 1 fixed).
  - SaaS default convention: treat `{your-domain}` as `{region}.aegaeon.cloud` (example:
    `apne1.aegaeon.cloud`), yielding issuers like `https://prod.acme.apne1.aegaeon.cloud`.
- **Control plane**: management API/UI, RBAC, audit, config versioning, SaaS-only features.
- **Data plane**: OAuth/OIDC runtime endpoints (`/authorize`, `/token`, discovery, JWKS, etc.).

## Product split (SaaS vs OSS)

### SaaS (full feature set)

- Multiple Teams/Tenants/Environments.
- Local admin authentication (Phase 1), with planned admin OIDC/Google sign-up (Phase 2+).
- RBAC (Owner/Administrator/Operator/Auditor/ReadOnly).
- Audit persistence + search + S3 export (Phase 1).
- MFA gates for high-risk operations (Phase 1 recommendation).

### OSS (reduced distribution)

- Single Team + single Tenant (fixed) + multiple Environments (optional).
- Local admin authentication required.
- Minimum operations: clients, keys, policies, configuration versioning.
- Audit via stdout/file (no S3 export or approval workflows).
- Feature reduction is implemented via deployment defaults and feature flags: the Management API and
  schema remain identical to the SaaS offering, while OSS builds pin identifiers
  (`teamId`, `tenantId`) and disable SaaS-only endpoints. Operators MAY re-enable
  multi-tenant capabilities by toggling the same flags.

Important: OSS feature reduction is not a security boundary. Open-source users can patch code and
re-enable functionality. Product differentiation should rely on hosted operation, enterprise
features, and operational tooling.

## Architecture: control plane vs data plane

### Boundary principles

- The data plane should be “read-mostly” from the management perspective:
  - read active configuration snapshots,
  - read keys/client registry/policies,
  - execute protocol flows.
- All configuration changes go through the control plane and must:
  - create a new configuration version,
  - be activated explicitly,
  - emit audit events.

### Admin console runtime boundary (normative)

The management UI is a first-party control-plane browser application. Its preferred runtime shape is
a browser-only SPA shell, not a claim-bearing server-rendered authentication surface.

Requirements:

- High-assurance management authentication, reauthentication, and step-up decisions MUST remain
  server-owned.
- The admin console MUST NOT become the system of record for management-session verification,
  privileged-action authorisation, or step-up grant issuance/consumption.
- Browser code MAY orchestrate platform ceremonies that require browser APIs (for example WebAuthn
  calls), but challenge issuance, assertion verification, session rotation, freshness checks, and
  one-time privileged-action grants MUST remain on the server.
- Introducing runtime SSR, a BFF, or a framework server mode is not required for stronger
  management-auth assurance and SHOULD NOT be treated as the primary mechanism for achieving it.
- If a server-rendered admin frontend is introduced later for operational reasons, it MUST preserve
  the same security boundary: server-owned management auth kernel, fail-closed management API, and
  no shift of credential-verification logic into UI-owned code paths.

### Configuration distribution (Phase 1)

Config snapshot pull:

- Data plane resolves `Host` to an Environment (fail-closed).
- Data plane reads `activeConfigurationVersionId` and pulls the active snapshot (ETag/hash).
- Hot reload is allowed where safe.

### Runtime command evidence and reconciliation

Management-triggered runtime mutations that cross from PostgreSQL control-plane state into Redis-backed
runtime state MUST create durable command evidence before touching runtime state. Commands that remain
active after the cleanup-derived stale window are reconciled by the server as `failed_unconfirmed` and
emit a control-plane audit event. This reconciliation is deliberately conservative: it closes the
operational evidence gap after a process crash without claiming whether a partially executed Redis
mutation did or did not happen.
