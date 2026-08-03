# Configuration scope redesign and migration plan

Last updated: 2026-07-07

Status: active plan

Owner: Architecture

Audience: architects, maintainers

This document defines the target configuration scopes for Aegaeon and a concrete
plan to migrate environment-variable settings into durable, management-controlled
configuration records. The software is pre-release, so we do **not** preserve
backward compatibility with existing environment-variable behavior.

## Goals

- Replace runtime environment-variable configuration with **scoped** settings:
  system, tenant, environment (issuer), and client (application).
- Store non-system scopes in the database and manage them via the Management API.
- Keep the data plane fail-closed and standards-first.
- Preserve operational clarity: each setting has a single authoritative home and
  a clear override/precedence order.

## Scope model (target)

### System (global process)
Infrastructure and process-level settings that must exist before the data plane
can start or that are shared across all tenants/environments.

- Storage: environment variables (bootstrap) and/or a privileged system config
  file/secret store. **Not** tenant-admin controllable.
- Examples: database connectivity, proxy trust, JWKS fetcher timeouts, KMS
  integration, logging, metrics exposure.

### Tenant (organizational defaults + constraints)
Defaults and guardrails that apply to all environments in a tenant.

- Storage: database (`tenant_settings`, `tenant_policy_defaults`).
- Used for: default policy posture, permitted sender-constrained methods,
  enforcement minima (e.g., "PKCE must be on"), shared rate limits.
- Tenant settings can **restrict** environment overrides but should not weaken
  system-level requirements.

### Environment (issuer-scoped)
Settings that directly affect OAuth/OIDC behavior for a single issuer.

- Storage: database (`environment_configuration_versions`) as a versioned
  configuration document.
- Controlled via the Management API, audited and versioned.
- Examples: OAuth policy gates, token lifetimes, OIDC enablement, mTLS metadata,
  DPoP policy, PAR TTL, DCR policy.

### Client / application (per OAuth client)
Client-specific capabilities and restrictions.

- Storage: database (`clients` and `client_policy_overrides`).
- Controlled via Management API (or DCR when allowed).
- Examples: redirect URIs, authentication methods, JWKS/keys, allowed grant
  types, and (optional) per-client policy overrides where permitted.

### Test / local-only
Test harness knobs and load-testing controls. These should **not** be stored in
production databases and should remain as local environment variables.

## Precedence and override rules

1. **System** sets hard minimums and infrastructure constraints.
2. **Tenant** provides defaults and constraints for environments.
3. **Environment** overrides tenant defaults (within tenant constraints).
4. **Client** overrides environment defaults only where explicitly allowed.
5. **Test/local** only applies in non-production harnesses.

Fail closed if required configuration is missing or invalid.

## Target mapping (current environment variables → target scope)

This mapping is defined **by section** of `docs/configurations/environment/README.md`.
Any exception is called out explicitly.

### Core identity & logging
Target scope:
- `BASE_URL` → **Environment**
- `RUST_LOG` → **System**
- `GIT_COMMIT` → **System** (build-time metadata only)

### Database (PostgreSQL / SQLx)
Target scope: **System**

### Management plane (Admin API)
Target scope: **System**

### Administrative endpoints (/admin/*)
Target scope: **System**

### Management data encryption
Target scope: **System**

### AWS KMS integration
Target scope: **System**

### Transport security (reverse proxy / forwarded headers)
Target scope: **System**

### Global security policy (RFC 9700 operator gates)
Target scope: **Environment**, with **Tenant** defaults and constraints.

### DPoP verification (RFC 9449)
Target scope:
- DPoP policy knobs (strictness, iat window, nonce enforcement) → **Environment**
- DPoP replay-store infrastructure (e.g., Redis URL) → **System**

### Authorization endpoint behaviour
Target scope: **Environment**, with optional tenant defaults.

### Token lifetimes
Target scope: **Environment**, with optional per-client overrides (future).

### Step-up authentication (RFC 9470)
Target scope: **Environment**

### Rich Authorization Requests (RFC 9396)
Target scope: **Environment**

### Token endpoint behaviour
Target scope: **Environment**

### Background cleanup tasks
Target scope: **System**

### Client authentication requirements
Target scope: **Environment**, with optional per-client overrides (future).

### OIDC runtime flags
Target scope: **Environment**

### private_key_jwt and request objects (JAR)
Target scope: **Environment**

### JWT bearer grant (RFC 7523)
Target scope: **Environment**

### Token exchange (RFC 8693)
Target scope: **Environment**

### JWT access tokens / JWT introspection response
Target scope: **Environment**

### Device authorization (RFC 8628)
Target scope: **Environment**

### JWKS fetching (for jwks_uri)
Target scope: **System**

### Dynamic Client Registration (DCR) and SSA verification
Target scope: **Environment** (policy) with **Tenant** defaults (optional).

### PAR (Pushed Authorization Requests)
Target scope: **Environment**

### OpenID Federation (OP mode)
Target scope: **Environment** (policy and cache TTLs).

### Upstream OIDC connections (federated logins)
Target scope: **System** (cache TTLs) + **Environment** (connection definitions).

### Discovery metadata (mTLS aliases)
Target scope: **Environment**

### Observability
Target scope: **System**

### JOSE policy knobs
Target scope: **System** (global hardening), optionally tenant defaults later.

### Test-only configuration
Target scope: **Test/local only** (remain as environment variables).

### Load testing
Target scope: **Test/local only** (remain as environment variables).

## Data model additions (management plane)

### System settings
Keep system settings outside tenant control:

- `system_settings` (optional, for UI visibility only):
  - `key`, `value`, `source` (env/config file), `last_updated_at`
  - Read-only via Management API (no writes).

### Tenant settings
Store default policies and constraints:

- `tenant_settings`:
  - `tenant_id`, `policy_defaults` (JSON), `policy_constraints` (JSON)
  - Versioned to preserve audit trails.

### Environment settings
Store issuer-scoped configuration as a versioned document:

- `environment_configuration_versions`:
  - `environment_id`, `version`, `document` (JSON), `published_at`, `published_by`
- `environment_configuration_current` (or a pointer on the `environments` table):
  - `environment_id`, `current_version`

### Client settings
Client metadata already exists; extend with:
- `client_policy_overrides` (JSON, optional)
- Explicit validation against environment policy constraints.

## Management API surface (additions)

- `GET /api/v1/system/config` (read-only snapshot, for operators)
- `GET/PATCH /api/v1/tenants/{tenantId}/policies`
- `GET/PATCH /api/v1/tenants/{tenantId}/policy-constraints`
- `GET /api/v1/environments/{environmentId}/configuration`
- `PATCH /api/v1/environments/{environmentId}/configuration` (creates new version)
- `POST /api/v1/environments/{environmentId}/configuration:publish`
- `GET/PATCH /api/v1/environments/{environmentId}/clients/{clientId}/policy-overrides`

All endpoints must validate against JSON Schema and enforce tenant constraints.

## Migration plan (no backward compatibility)

### Phase 0 — Documentation + schema definition
- Publish this document and the initial JSON Schemas for:
  - `tenant_policy_defaults`
  - `tenant_policy_constraints`
  - `environment_configuration`
  - `client_policy_overrides`
- Define canonical config keys and defaults (no implicit env fallbacks).

### Phase 1 — Storage + API wiring
- Add tables for tenant and environment configuration versions.
- Implement Management API endpoints with strict validation.
- Write migration/seed scripts for local dev (`scripts/dev/seed_environment_config`).

### Phase 2 — Data plane config resolution
- Implement a configuration resolver:
  - Load system settings from env/secrets.
  - Load environment configuration by issuer host.
  - Apply tenant defaults/constraints.
  - Apply client overrides where allowed.
- Cache resolved configs with short TTL; invalidate on publish.

### Phase 3 — Remove environment-variable reads (env/config scope)
- Delete env var reads for environment-scoped settings.
- Make environment configuration required for data plane startup.
- Keep system + test-only env vars.

### Phase 4 — UI/SDK integration
- Management UI and TS SDK manage tenant/environment configs.
- Add diff views between versions, audit trails, and rollback.

### Phase 5 — Cleanup + enforcement
- Remove deprecated docs, scripts, and env var references.
- Add CI checks to prevent new env var usage in data plane logic.

## Non-goals (initial)

- Complex per-tenant “policy scripting” engines.
- Dynamic per-request policy evaluation beyond config gating.
- Auto-migration of legacy env var deployments.

## Acceptance criteria

- All runtime OAuth/OIDC behavior is driven by environment+tenant+client
  configuration stored in the database.
- System-only settings are the only remaining environment variables in
  production deployments.
- Management API serves as the single source of truth for configuration changes.
