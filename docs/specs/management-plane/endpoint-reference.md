# Management Plane Endpoint Reference

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Management API endpoint skeleton (Phase 1)

All identifiers are UUIDv4 unless otherwise stated.

### Authentication / bootstrapping

- `POST /api/v1/authentication/sessions` (local login)
- `DELETE /api/v1/authentication/sessions/current` (logout)
- `POST /api/v1/bootstrapping/owners` (bootstrap first Owner; one-time)

### Teams

- `GET /api/v1/teams`
- `POST /api/v1/teams`
- `GET /api/v1/teams/{teamId}`
- `PATCH /api/v1/teams/{teamId}`
- `DELETE /api/v1/teams/{teamId}`

### Team API keys

- `GET /api/v1/teams/{teamId}/apiKeys`
- `POST /api/v1/teams/{teamId}/apiKeys`
- `POST /api/v1/teams/{teamId}/apiKeys/{apiKeyId}/revoke`

### Tenants

- `GET /api/v1/teams/{teamId}/tenants`
- `POST /api/v1/teams/{teamId}/tenants`
- `GET /api/v1/teams/{teamId}/tenants/{tenantId}`
- `PATCH /api/v1/teams/{teamId}/tenants/{tenantId}`
- `DELETE /api/v1/teams/{teamId}/tenants/{tenantId}`

### Environments

- `GET /api/v1/teams/{teamId}/tenants/{tenantId}/environments`
- `POST /api/v1/teams/{teamId}/tenants/{tenantId}/environments`
- `GET /api/v1/teams/{teamId}/environments/{environmentId}`
- `PATCH /api/v1/teams/{teamId}/environments/{environmentId}`
- `DELETE /api/v1/teams/{teamId}/environments/{environmentId}`

### Configuration versions

- `GET /api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions`
- `GET /api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}/activate`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}/archive`

### Policies (shortcut over config versions)

- `GET /api/v1/teams/{teamId}/environments/{environmentId}/policies`
- `PATCH /api/v1/teams/{teamId}/environments/{environmentId}/policies`
  - internal behaviour: create + activate a new configuration version

### Clients

- `GET /api/v1/teams/{teamId}/environments/{environmentId}/clients`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/clients`
- `GET /api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}`
- `PATCH /api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}`
- `DELETE /api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}`

### Client secrets

- `GET /api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets/{clientSecretId}/revoke`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets/revokeAll`

### Runtime keys and keystore configuration

- `GET /api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys/activateNext`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys/{runtimeKeyId}/revoke`

- `GET /api/v1/teams/{teamId}/environments/{environmentId}/keyStores/current`
- `PUT /api/v1/teams/{teamId}/environments/{environmentId}/keyStores/current`

### Users (Phase 1 minimal)

- `GET /api/v1/teams/{teamId}/environments/{environmentId}/users?query=...`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/block`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/unblock`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/invalidateSessions`
- `POST /api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/revokeRefreshTokens`

### Audit events

- `GET /api/v1/teams/{teamId}/auditEvents`
- `GET /api/v1/teams/{teamId}/environments/{environmentId}/auditEvents`
- `GET /api/v1/teams/{teamId}/auditEvents/{auditEventId}`

### System

- `GET /api/v1/system/health`
- `GET /api/v1/system/version`

## OpenAPI generation (repository workflow)

OpenAPI contracts for the management plane and operational endpoints are generated from code and
committed:

- Generate: `cargo xtask openapi`
- Check (CI-friendly): `cargo xtask openapi --check`
- Artifacts:
  - `generated/openapi/aegaeon-management-api.v1.json`
  - `generated/openapi/aegaeon-ops.v1.json`
  - `generated/openapi/swagger-ui.html`

### OpenAPI web view (Swagger UI)

`generated/openapi/swagger-ui.html` is a static Swagger UI entrypoint that loads the committed JSON
specs. Serve `generated/openapi/` over HTTP and open the page in a browser:

```bash
cd generated/openapi
python3 -m http.server 8000
```

Then open `http://localhost:8000/swagger-ui.html`.

### OpenAPI source mapping

- OpenAPI annotations: `crates/server/src/openapi/management.rs`, `crates/server/src/openapi/ops.rs`
- Schema/types: `crates/server/src/openapi/types.rs`
- Generator: `xtask/src/main.rs` (`cargo xtask openapi`)
