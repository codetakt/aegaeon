# Management plane architecture (Org/Tenant/Environment)

Last updated: 2026-07-07

Status: active plan

Owner: Architecture

Audience: architects, maintainers

This document defines the target management-plane model for Aegaeon and the invariants that must
hold as we add “practical operations” features (multi-tenancy, admin APIs, key management, audit,
etc.) while preserving the standards-first, fail-closed posture of the verified-first OAuth/OIDC data
plane.

## Goals

Verification posture note (2026-03-08): the data plane is intentionally split between the
modern verified allowlist and the broader compat runtime. If product positioning requires an
unqualified “verified OIDC Core” statement, the planned OIDC `RS256` slices must be closed
without silently expanding the general verified allowlist.

- Keep the OAuth/OIDC **data plane** small, predictable, and standards-first.
- Add a feature-rich **control plane** (Auth0-style management) without expanding the trusted
  computing base of the data plane unnecessarily.
- Make `issuer` **domain-based** (host-based) and treat it as the primary security boundary for
  OpenID Connect.
- Support SaaS and Enterprise deployments with the same conceptual model.

## Non-goals (for now)

- Perfect Auth0 feature parity (Rules/Actions, marketplace integrations, full SaaS billing, etc.).
- Enforcing “OSS restrictions” as a security boundary (open-source users can patch code).

## Terms & hierarchy

The management hierarchy is Auth0-inspired, but we intentionally make **Environment the OIDC
boundary**.

- **Org**: top-level account boundary (contract/billing/ownership). Contains Teams and Tenants.
- **Team**: grouping of admin principals for RBAC (permissions over one or more Tenants).
- **Tenant**: operational unit under an Org. Contains Environments. May carry default policy and
  naming constraints.
- **Environment**: the unit that owns an `issuer` (host), signing keys, client registry, and policy
  gates. **One Environment corresponds to exactly one OIDC issuer.**

## Issuer and domain model (host-based)

### Invariants

- Each Environment has exactly one canonical issuer:
  - `issuer = https://<env-domain>` (no trailing slash; canonical form).
- Discovery and JWKS are published under the same host:
  - `https://<issuer>/.well-known/openid-configuration`
  - `https://<issuer>/.well-known/jwks.json`
- Runtime request handling must be **fail-closed**:
  - If `Host` cannot be resolved to an Environment, return a 4xx (prefer `404` or `421`).
- Public URLs and tokens must use the configured issuer (not the inbound request host):
  - Prevent Host header injection / proxy confusion from changing `iss` or endpoint URLs.

### SaaS default domain convention

For the managed offering, we standardise on:

- `https://{environment}.{tenant}.{region}.aegaeon.cloud`
  - Example: `https://prod.acme.apne1.aegaeon.cloud`

Rationale:

- Enables zone delegation for operational separation.
- Enables tenant-scoped wildcard certificates (`*.{tenant}.{region}.aegaeon.cloud`).
- Keeps migration paths open (move a tenant between ingress cells without changing issuer).

### DNS delegation (recommended)

The hierarchy is designed to allow delegation of authority (DNS + certificate issuance processes):

1. Root zone:
   - `aegaeon.cloud`
2. Region sub-zone (delegated):
   - `{region}.aegaeon.cloud` (example: `apne1.aegaeon.cloud`)
3. Tenant sub-zone (optionally delegated further):
   - `{tenant}.{region}.aegaeon.cloud` (example: `acme.apne1.aegaeon.cloud`)
4. Environment records live inside the tenant zone:
   - `{environment}.{tenant}.{region}.aegaeon.cloud` → ALIAS/A/AAAA to the data-plane ingress.

Operational notes:

- Region/tenant zones can be delegated to separate AWS accounts (“cells”) without changing the
  public issuer format.
- For ingress indirection, prefer pointing environment records to stable “ingress names”
  (e.g. `ingress-1.apne1.aegaeon.cloud`) rather than directly to an ALB hostname.

### Certificate strategy

To keep the operational blast radius small, issue certificates at the tenant zone boundary:

- Tenant wildcard certificate:
  - `*.{tenant}.{region}.aegaeon.cloud`
  - Example: `*.acme.apne1.aegaeon.cloud`

This covers all Environment issuers for that Tenant/Region (`prod.*`, `stg.*`, `dev.*`) with a
single certificate and allows certificate issuance to be delegated alongside the tenant zone.

## Control plane vs data plane

### Data plane responsibilities (OIDC runtime)

- Serve OAuth/OIDC endpoints for a resolved Environment.
- Read configuration, keys, client registry, and policy gates from a configuration source.
- Maintain runtime state (authorisation codes, refresh tokens, PAR handles, replay stores, etc.)
  consistent with the standards-first posture and existing verification artefacts.
- Enforce transport/trust boundaries (see `docs/configurations/networking.md`).

The data plane should avoid owning complex admin workflows and should not need to understand Org or
Team membership.

### Control plane responsibilities (management)

- Manage Org/Team/Tenant/Environment lifecycle and RBAC.
- Provision and validate domains (issuer hosts) and associated certificates.
- Manage environment-scoped configuration:
  - policy toggles (PKCE, sender-constrained requirements, algorithm allowlists, TTLs)
  - crypto profile selection per instance (verified vs compat allowlist)
  - JWKS and key rotation policies
  - client registration policies (DCR on/off, allowed metadata)
- Provide audit logging and export pipelines.
- Provide admin authentication (SSO) and operational workflows (break-glass access, approvals).

### Deployment options

Prefer a hard boundary (separate service / separate network plane) when possible:

- **Recommended**: separate `aegaeon-admin` (control plane) and `aegaeon-server` (data plane).
- Acceptable for early development: single process with strict route segregation (`/admin/*`) and
  separate auth, rate limits, and network policies.

## Management API surface (draft)

The control plane should expose a stable REST API (“Management API”) that backs any UI/CLI/Terraform
integration. Endpoints below are illustrative and can be refined.

Phase 1 naming conventions:

- Use `/api/v1` as the base prefix.
- Avoid shortened path segments (use `organizations`, `tenants`, `environments`).

For the Phase 1 resource model and endpoint skeleton, see:

- `docs/specs/management-plane/README.md`

### Core hierarchy (illustrative)

- `GET/POST /api/v1/organizations`
- `GET/POST /api/v1/organizations/{organizationId}/tenants`
- `GET/POST /api/v1/organizations/{organizationId}/tenants/{tenantId}/environments`

### Domain / issuer management

- `GET/POST /api/v1/.../environments/{environmentId}/domains`
  - register `{environment}.{tenant}.{region}.aegaeon.cloud` or a custom domain
- `POST /api/v1/.../environments/{environmentId}/domains/{domainId}:verify`
  - DNS/TXT or CNAME verification (if using custom domains)
- `POST /api/v1/.../environments/{environmentId}/domains/{domainId}:activate`
  - make the domain the active issuer for the Environment

### Client and key management

- `GET/POST /api/v1/.../environments/{environmentId}/clients`
- `GET/PATCH/DELETE /api/v1/.../environments/{environmentId}/clients/{clientId}`
  - `DELETE` is bodyless; send `aegaeon-base-configuration-version-id` for the configuration
    precondition.
- `POST /api/v1/.../environments/{environmentId}/clients/{clientId}/clientSecrets`
- `GET/POST /api/v1/.../environments/{environmentId}/signingKeys`
- `POST /api/v1/.../environments/{environmentId}/signingKeys/rotate`

### Policy and audit

- `GET/PATCH /api/v1/.../environments/{environmentId}/policies`
- `GET /api/v1/.../auditEvents?since=...`
- `GET /api/v1/.../auditExports` / `POST /api/v1/.../auditExports`

Future expansions (deferred):

- Connections (external IdP integration): `/v1/environments/{environment_id}/connections`
- End-user directory (DB users) and sessions: `/v1/environments/{environment_id}/users`,
  `/v1/environments/{environment_id}/sessions`

## Data model (draft)

At minimum, the control plane needs durable identifiers and strict scoping:

- `orgs(id, slug, ...)`
- `teams(id, org_id, name, ...)`
- `tenants(id, org_id, slug, region, ...)`
- `environments(id, tenant_id, name, issuer, status, ...)`
- `environment_domains(id, environment_id, domain, is_custom, verified_at, active, ...)`
- `clients(id, environment_id, ...)`
- `keys(id, environment_id, ...)`
- `audit_events(id, org_id, tenant_id, environment_id, actor, action, before, after, timestamp, ...)`

Security requirement:

- All data access must be scoped by the caller’s authorisation context (Org/Team/Env) and must not
  allow cross-tenant reads/writes.

## OSS / Enterprise positioning (practical note)

If the code is open-sourced, “feature restriction” cannot be treated as a security boundary:
users can patch code or build custom binaries. Product differentiation should rely on:

- hosted operation (SaaS SLOs), support, and compliance artefacts,
- Enterprise distribution and operational tooling (SSO/RBAC integration, audit exports, approvals),
- managed domain/certificate automation, and
- validated deployment recipes.

The architecture above remains valid regardless of whether the control plane is distributed as OSS
or as an Enterprise-only component.

## Roadmap (management plane)

This is an implementation-oriented sequencing guide (not a sprint plan).

1. **Environment resolution + issuer invariants**
   - Host → Environment resolver (fail-closed).
   - Ensure all public metadata and tokens use the configured issuer.
2. **Management API foundation**
   - Admin authentication + RBAC scaffolding.
   - CRUD for Org/Tenant/Environment (minimal fields).
3. **Domain and certificate lifecycle**
   - Default SaaS domains and zone delegation conventions.
   - Custom domain verification + activation.
4. **Client and key management**
   - Client CRUD + secret rotation.
   - Key rotation workflows with audit trails.
5. **Audit events and exports**
   - Append-only audit log.
   - Export to S3 (and later Webhook/SIEM).
6. **Connections and user directory (if required)**
   - External IdP integrations and claims mapping (declarative).
   - Optional DB user directory and session management.

## Phase 1 decisions

- Region label format: standardise on AWS-like abbreviations (example: `apne1`) for the managed
  offering.
- Issuer changes and custom domain migration: Phase 1 treats issuer as immutable; changing issuer
  requires creating a new Environment (custom domain verification/activation is deferred).
- Team semantics: Teams are an RBAC grouping concept and are deferred to Phase 2+; Phase 1 models
  Organization/Tenant/Environment only.
