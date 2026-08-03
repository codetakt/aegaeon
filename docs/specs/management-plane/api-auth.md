# Management Plane API and Authorization

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Management API conventions

### Base URL and versioning

- Base path: `/api/v1`
- Breaking changes require `/api/v2` while keeping `/api/v1` stable.

### Naming rules

- Do not use shortened path segments:
  - use `teams`, `tenants`, `environments`, `configurationVersions`, etc.
- JSON keys use `camelCase`.

### Team scoping (Phase 1; normative)

Phase 1 assumes that an administrator may belong to multiple Teams. Management API authorisation MUST
NOT rely on an implicit “current team” stored in session state.

Requirements:

- Any Team-scoped operation MUST include `teamId` in the request URI.
  - Example: `/api/v1/teams/{teamId}/...`
- The server MUST validate that the referenced resource belongs to the `teamId` in the URI.
- If the `teamId` does not match the target resource, the server MUST fail closed.
  - Recommended: return `404` to avoid leaking cross-team resource existence.

Exceptions (not Team-scoped):

- `POST /api/v1/authentication/sessions`
- `DELETE /api/v1/authentication/sessions/current`
- `POST /api/v1/bootstrapping/owners`
- `GET /api/v1/teams` (list teams visible to the caller)
- `POST /api/v1/teams` (create team; SaaS-only)
- `GET /api/v1/system/health`
- `GET /api/v1/system/version`

### Path hierarchy shortcuts (Phase 1; normative)

The resource model is hierarchical (Team → Tenant → Environment), but Phase 1 uses UUIDv4
resource identifiers. When an identifier is globally unique, the API MAY omit intermediate parents
from read/update/delete paths for ergonomics, while still treating `teamId` as the explicit
authorisation context.

Requirements:

- Short paths MUST still include `teamId`.
- The server MUST validate that the target resource belongs to `teamId` (and therefore to a Tenant
  within that Team).
- If the ownership check fails, the server MUST fail closed (recommend `404`).

Environment paths (Phase 1 decision):

- Environments are created and listed under a Tenant:
  - `GET/POST /api/v1/teams/{teamId}/tenants/{tenantId}/environments`
- Individual Environment operations use a short path without `tenantId`:
  - `GET/PATCH/DELETE /api/v1/teams/{teamId}/environments/{environmentId}`

### Error envelope (example)

```json
{
  "errorCode": "CLIENT_SECRET_ROTATION_REQUIRED",
  "message": "Client secret must be rotated before 2026-01-31.",
  "details": {
    "clientId": "uuid",
    "deadline": "2026-01-31"
  },
  "requestId": "req_..."
}
```

### Pagination

- `pageSize` (max 200)
- `pageToken` (opaque)

### Concurrency control

- For configuration changes, require `baseConfigurationVersionId` and return `409` on conflict.
  JSON write methods carry this value in the request body. Bodyless `DELETE` configuration
  mutations carry it in the `aegaeon-base-configuration-version-id` header; management `DELETE`
  requests do not accept JSON request bodies.
- Optionally also support `If-Match` with an ETag hash.

### REST-first contract (why not GraphQL in Phase 1)

Phase 1 standardises on a REST-ish HTTP API described in OpenAPI. The admin console can optionally
introduce a BFF later (including GraphQL), but the control plane API remains REST-first.

Rationale:

- **Auditability**: management actions map 1:1 to well-scoped endpoints and HTTP methods, making
  audit event generation and review straightforward and consistent.
- **Explicit authorisation context**: Team scoping is explicit in the request URI (no hidden
  “current team” state), which simplifies RBAC enforcement and fail-closed behaviour.
- **Reduced attack surface**: GraphQL introduces additional operational/security considerations
  (query complexity limits, introspection posture, persisted queries, resolver-level auth), which
  are unnecessary for Phase 1 delivery.
- **Stable shared contract**: OpenAPI output is used as the shared contract between backend and UI
  repositories; schema drift is detectable via CI and versioned artefacts.

If a BFF is introduced, it MUST NOT become the system of record: it should delegate to the REST API
or database-backed services that already enforce RBAC and emit audit events, and it must apply
query-level safeguards (depth/complexity limits, persisted queries) appropriate for the deployment.

### Responses for configuration transactions

In Phase 1, Environment state is configuration-snapshot-driven. Any management operation that
mutates Environment-scoped resources (clients, secrets, policies, signing keys, keystore) must be
implemented as a configuration transaction.

When a request results in an Environment mutation, implementations should return the updated
Environment state, or at minimum the updated `activeConfigurationVersionId`, so admin UIs can
reconcile state deterministically.

## Authentication and authorisation (Phase 1)

Phase 1 uses local administrator accounts stored in the control-plane database.

- Bootstrap:
  - allow creating the first Owner exactly once,
  - disable bootstrap after completion,
  - emit an audit event.
  - deployments SHOULD protect this operation with an operator-configured bootstrap token (for example
    `AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN`) to reduce the risk of "fresh DB takeover" during initial
    provisioning.
- Admin console sessions:
  - prefer HttpOnly/Secure cookie sessions for the browser UI.
- Automation access (PATs) is optional in Phase 1 and may be deferred to Phase 2.

### CSRF protection (cookie sessions; Phase 1)

If the management plane uses cookie-based sessions, Phase 1 must not rely on `SameSite` alone.
Write requests must be protected with a CSRF token and an origin check.

Requirements:

- Session cookie:
  - `HttpOnly; Secure; SameSite=Lax`
- All write operations (`POST`/`PUT`/`PATCH`/`DELETE`) MUST:
  - require an `X-CSRF-Token` header,
  - require `Origin` to match the admin console origin (reject mismatches with `403`),
  - require `Content-Type: application/json` (reject form/multipart content types).

Recommended token scheme (double-submit):

- Set a `csrf_token` cookie that is readable by browser JS (not `HttpOnly`).
- Clients must copy it into `X-CSRF-Token`.
- Servers validate cookie/header equality and origin.

## RBAC (Phase 1)

### Roles

- Owner
- Administrator
- Operator
- Auditor
- ReadOnly

### Permission matrix (Phase 1; normative)

The matrix below defines the minimum intended authorisation model for Phase 1. Deployments MAY
further restrict permissions.

| Capability | Owner | Administrator | Operator | Auditor | ReadOnly |
|-----------|-------|---------------|----------|---------|----------|
| Read team/tenant/environment state | ✅ | ✅ | ✅ | ✅ | ✅ |
| Read configuration versions and policies | ✅ | ✅ | ✅ | ✅ | ✅ |
| Read audit events | ✅ | ✅ | ✅ | ✅ | ✅ |
| Manage team/tenant/environment lifecycle | ✅ | ✅ | ❌ | ❌ | ❌ |
| Create/archive/activate configuration versions | ✅ | ✅ | ❌ | ❌ | ❌ |
| Patch policies / keystore configuration | ✅ | ✅ | ❌ | ❌ | ❌ |
| Client registry: create/update | ✅ | ✅ | ✅ | ❌ | ❌ |
| Client registry: delete | ✅ | ✅ | ❌ | ❌ | ❌ |
| Client secrets: issue/revoke | ✅ | ✅ | ❌ | ❌ | ❌ |
| Signing keys: rotate/activate/revoke | ✅ | ✅ | ❌ | ❌ | ❌ |
| User operations (Phase 1 minimal) | ✅ | ✅ | ✅ | ❌ | ❌ |
| Team API keys: create/revoke | ✅ | ✅ | ❌ | ❌ | ❌ |

### Management API keys (Phase 1; normative)

Management API keys are Team-scoped, database-backed service principals. They are not process-local
secrets and MUST NOT be configured through startup environment variables.

Requirements:

- API keys MUST be stored in PostgreSQL as hashed key material plus a service administrator row.
- API key authentication MUST load the API key, its service principal, team binding, and capability
  set from PostgreSQL on each request or through a cache whose invalidation is database-backed and
  fail-closed.
- API keys MUST include a non-empty capability set at creation time.
- Supported capabilities are:
  - `read`
  - `auditRead`
  - `teamAdministration`
- Service-principal team role MUST be `READONLY` for every capability set. It is only a visibility
  envelope for existing RBAC joins. API-key sessions MUST still pass endpoint-specific capability
  checks and MUST NOT inherit human lifecycle authority from the service administrator row.
- `teamAdministration` is the only super-capability. Other capabilities MUST NOT implicitly grant
  lifecycle or policy mutation permissions.
- `read` and `auditRead` authorize read/audit surfaces within the same team subject to the
  service-principal visibility envelope.
- API-key lifecycle is human-session only. API keys MUST NOT create, rotate, or revoke API keys.
- API-key list by API key MUST require same-team membership plus `read` or `teamAdministration`.
- `lastUsedAt` updates SHOULD be throttled to avoid a write on every authenticated request.

### High-risk operations (MFA gate; SaaS Phase 1 recommendation)

- issuer activation/replacement,
- signing key rotation/revocation,
- client deletion,
- client secret issuance/revocation/revokeAll,
- policy changes that weaken posture (e.g. enabling DCR, loosening alg allowlists),
- audit export configuration changes.

Recommended implementation posture:

- treat these operations as requiring fresh management assurance rather than only an existing
  long-lived management session,
- implement any reauthentication / step-up as a dedicated server-owned management-auth surface,
- bind successful step-up to a short-lived, action-scoped, one-time grant or equivalent server-side
  state so replay and cross-action reuse fail closed.

Current server minimum:

- high-risk mutations reject management API-key service-principal sessions and require an
  interactive human management session,
- team lifecycle role checks reject service administrators even when their derived DB role is
  `ADMINISTRATOR`,
- stronger MFA/WebAuthn or action-scoped one-time grants remain the hosted/enterprise step-up layer
  above this fail-closed baseline.
