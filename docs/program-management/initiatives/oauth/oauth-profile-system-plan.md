# OAuth Profile System Plan

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

Objective: keep downstream client and upstream provider policy selection explicit without making
unsupported legacy OAuth flows representable.

## Current Design

- Profiles are scoped to an environment and configuration version.
- Profiles are either `DOWNSTREAM` or `UPSTREAM`.
- Profiles are code-flow only:
  - PKCE is mandatory.
  - response type is not configurable; authorization uses `code` only.
  - `allowed_grant_types` cannot contain `password`.
- Profiles may still narrow implemented capabilities:
  - grant allowlist
  - token endpoint authentication methods
  - sender constraint
  - state and issuer-identification requirements
  - refresh sender-binding enforcement
- Expired or retired profiles fail closed.

## Persistence

The authoritative schema is `db/schema.sql`.

The `oauth_profiles` table intentionally has no version selector and no implicit/password
compatibility toggles. The database enforces the same modern-flow shape as the management API:

```sql
CHECK (
  require_pkce
  AND NOT ('password' = ANY(allowed_grant_types))
)
```

## Management API

Base path: `/api/v1/teams/:teamId/environments/:environmentId`.

- `GET /oauthProfiles`
- `POST /oauthProfiles`
- `GET /oauthProfiles/:profileId`
- `PATCH /oauthProfiles/:profileId`
- `DELETE /oauthProfiles/:profileId`
- `PATCH /clients/:clientId`
- `PATCH /connections/:connectionId`

Example profile request:

```json
{
  "name": "downstream-default",
  "description": "Default downstream code-flow profile",
  "profileType": "DOWNSTREAM",
  "isDefault": true,
  "requirePkce": true,
  "requireStateParameter": true,
  "requireIssParameter": false,
  "senderConstrained": "DPOP",
  "enforceRefreshSenderBinding": true,
  "allowedGrantTypes": ["authorization_code", "refresh_token"],
  "tokenEndpointAuthMethodsAllowed": ["client_secret_basic", "client_secret_post"],
  "expiresAt": null
}
```

## Enforcement Points

- `/authorize`: fixed `response_type=code`, PKCE, state, issuer identification, and profile grant constraints.
- `/token`: grant type, client authentication method, sender binding, and refresh binding.
- DCR: declared metadata must not exceed the default downstream profile.
- Upstream flows: discovery and authorize/refresh handling must satisfy the bound upstream profile.

## Status

- Management CRUD, audit events, and profile assignment are implemented.
- Runtime profile resolution is implemented for downstream and upstream paths.
- Legacy compatibility fields were removed before release; no backward compatibility is promised.
