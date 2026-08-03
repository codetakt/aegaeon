# Admin Console frontend handoff (Phase 1)

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Engineering

Audience: contributors, maintainers

> **Status note (2026-04-22):** This is an implementation-facing handoff brief. The authoritative API contract lives in the generated OpenAPI documents it references, the broader product model lives in `docs/specs/management-plane/README.md`, and the current browser implementation lives in the sibling `../aegaeon-admin-console` repository.

This document is for the `aegaeon-admin-console` frontend implementation team.
It focuses on **behavior and integration** (not visual design).

## Scope and assumptions

- The backend exposes a **cookie-based** management API under `http(s)://<host>/api/v1/*`.
- The API is **Team-scoped**: callers must provide `teamId` in the URI for Team-scoped operations.
- The issuer/security boundary is **Environment** (one Environment == one OIDC issuer).
- The admin console runs in a browser and must send requests with **credentials** enabled.
- The current admin-console boundary is source-managed in `../aegaeon-admin-console/spec/admin-sdk-boundary.current.json`: use `@aegaeon/management-client` for management-plane transport and keep OIDC/RP packages out of the console unless management authentication explicitly moves onto OIDC.
- The current management-auth boundary is source-managed in `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`: management login stays on the cookie-based management-session flow, and app sources must not hand-roll cookie / CSRF / bearer-token auth logic.
- The planned SDK source-language migration does not change that boundary: the admin console should keep consuming SDK package exports, not SDK source-tree internals, regardless of whether the SDK implementation moves from handwritten JavaScript to TypeScript.
- The preferred frontend runtime shape remains a browser SPA shell. If the sibling console uses
  React Router 7, prefer SPA mode over runtime server mode / SSR for the control-plane UI.
- Stronger management authentication assurance does not require widening the UI runtime boundary:
  management reauthentication and step-up should be added as server-owned flows, not by making the
  admin console itself a claim-bearing authentication server.
- If Aegaeon later grows a local credential plane for primary-authority end users, that credential UI should be delivered as a separate **server-handled issuer/auth surface**, not as an expansion of the current admin SPA. The admin console may configure or audit that plane, but must not become the browser endpoint that owns end-user password / reset / MFA / WebAuthn submission.

## Artifacts to consume

- OpenAPI (source of truth):
  - `generated/openapi/aegaeon-management-api.v1.json`
  - `generated/openapi/aegaeon-ops.v1.json`
- Swagger UI (static viewer):
  - `generated/openapi/swagger-ui.html` (loads the JSON above)
- Local dev compose (backend + Postgres 18):
  - `tests/docker/docker-compose.management-ui.yml`
- Sibling reference implementation:
  - `../aegaeon-admin-console`
  - current SDK boundary: `../aegaeon-admin-console/spec/admin-sdk-boundary.current.json`
  - current auth boundary: `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`
  - current compose-backed browser lane: `../aegaeon-admin-console/docker-compose.aegaeon.yml`
- Management plane spec (data model + rationale):
  - `docs/specs/management-plane/README.md`

## Local development quick start (backend)

Prereqs: Docker + Docker Compose (Nix is optional but recommended for reproducible builds).

1) Build the server image:

```bash
nix run .#docker-build
```

1) Start Postgres + server:

```bash
docker compose -f tests/docker/docker-compose.management-ui.yml up -d
```

1) Confirm the management API is reachable:

- `GET http://localhost:8080/api/v1/system/health` → `OK`

1) OpenAPI review locally (Swagger UI):

```bash
cd generated/openapi
python3 -m http.server 8000
```

Open: `http://localhost:8000/swagger-ui.html`

1) Full UI stack (SDK-backed admin console, sibling repo):

- The sibling `../aegaeon-admin-console` repository now drives this backend through
  `@aegaeon/management-client`.
- Its compose-backed checks (`pnpm stack:smoke`, `pnpm stack:e2e`) build the multi-stage Dockerfile
  from this repository and currently exercise bootstrap, login, dashboard rendering, and real
  management mutations through the SDK boundary.

## Browser security model (cookie + CSRF + Origin)

The management API uses:

- Session cookie: `aegaeon_admin_session` (HttpOnly, `Path=/api/v1`)
- CSRF cookie: `csrf_token` (not HttpOnly, `Path=/`)
- Write-method guard: **Origin allowlist + double-submit cookie**

### Required behavior in the frontend

1) Always send cookies:

- The browser transport must use `credentials: "include"`; the current admin-console implementation delegates that to `@aegaeon/management-client`.

1) Prime the CSRF cookie before any write request:

- Call a read endpoint first (recommended: `GET /api/v1/system/health`).
- The middleware sets `csrf_token` if missing.

1) For **all** write requests (`POST/PUT/PATCH/DELETE`):

- The browser must send an `Origin` header that matches the server allowlist.
  - In the supported management-database runtime, configure
    `aegaeon.control_plane_policies.management_allowed_origins`.
- Set `X-CSRF-Token: <value-of-csrf_token-cookie>`.
- Use `Content-Type: application/json` for JSON bodies.

If the CSRF/origin checks fail, the API returns `403` with `errorCode` such as:
`csrf_origin_required`, `csrf_origin_unconfigured`, `csrf_origin_mismatch`,
`csrf_missing`, `csrf_mismatch`.

## Bootstrap and login flows

### Bootstrap (first-owner)

Endpoint: `POST /api/v1/bootstrapping/owners`

- One-time operation: once any administrator exists, the endpoint returns `409 bootstrap_completed`.
- If the server is configured with `AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN`, the request JSON must include
  `bootstrapToken`. Errors:
  - `403 bootstrap_token_required`
  - `403 bootstrap_token_mismatch`

Frontend recommendation:

- Provide a “First time setup” screen (separate from sign-in).
- On submit:
  - success `204` → redirect to sign-in
  - `409 bootstrap_completed` → show “Already initialised; please sign in”

### Login / logout

- Login: `POST /api/v1/authentication/sessions` with `{ email, password }`
  - success `204` sets `aegaeon_admin_session`
  - failure `401 invalid_credentials`
- Logout: `DELETE /api/v1/authentication/sessions/current`
  - success `204` clears the session cookie

Both endpoints are write methods, so they require the CSRF/origin rules above.

Frontend recommendation:

- On app start, call `GET /api/v1/system/health` to ensure the CSRF cookie exists.
- Use `GET /api/v1/teams` as the primary “am I authenticated?” probe:
  - `200` → authenticated
  - `401` → show sign-in
- Treat this management-session flow as the current security boundary. If management authentication
  ever moves onto OIDC, update `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`,
  regenerate admin SDK evidence, and add new threat-model and E2E coverage before widening the
  console boundary.

## Management reauthentication / step-up posture

If high-assurance administrator reauthentication or step-up is added:

- keep the admin console as a browser SPA and route all security-critical decisions through the
  server-owned management-auth surface,
- allow browser participation only where platform APIs require it (for example WebAuthn
  ceremony calls),
- keep challenge issuance, assertion verification, management-session freshness checks, step-up
  grant issuance, and step-up grant consumption on the server,
- do not move password / TOTP / WebAuthn verification logic into client-side route loaders,
  actions, or ad hoc fetch wrappers,
- do not treat runtime SSR or a framework server mode as the assurance boundary; the assurance
  boundary remains the management API plus any dedicated management-auth endpoints.

## IA: page map (Auth0-style split)

Auth0’s separation maps well to:

- **Team-level**: membership/role boundaries, tenant creation, team-wide audit.
- **Environment-level (issuer)**: day-to-day ops (configuration, policies, clients, keys, audit).

Recommended high-level layout:

- Global header:
  - Team selector
  - Tenant selector (scoped to selected Team)
  - Environment selector (scoped to selected Tenant)
  - Current issuer display (read-only)
- Left navigation (when an Environment is selected):
  - Overview
  - Configuration Versions
  - Policies
  - Clients
  - Keys / Keystore
  - Users (local lifecycle, credentials, profile, and token/session inventory)
  - Audit

## Implemented endpoints and current UI coverage

As of this handoff, the backend implements:

- System: `GET /api/v1/system/health`, `GET /api/v1/system/version`
- Auth: `POST /api/v1/authentication/sessions`, `DELETE /api/v1/authentication/sessions/current`
- Bootstrap: `POST /api/v1/bootstrapping/owners`
- Teams: list/create/get/update/delete
- Tenants: list/create/get/update/delete
- Environments: list/create/get/update/delete
- Connections: list/create/get/update/delete
- Configuration Versions: list/create/get/activate/archive
- Policies: `GET/PATCH /api/v1/teams/{teamId}/environments/{environmentId}/policies`
- Clients: list/create/get/update/delete
- Client secrets: list/issue/revoke/revoke-all
- Signing keys and keystore views/updates
- Users: list/create/update/delete/restore, include-deleted listing, suspend/restore, profile
  get/update, credential inspection, activation/password-reset issuance, password/recovery-token
  revoke, session/grant/refresh-token inventory with selective revoke, invite, and CSV import
- Audit: team/environment audit reads and event detail

The current sibling `../aegaeon-admin-console` compose-backed browser lane exercises the following
through `@aegaeon/management-client`:

- bootstrap owner
- login and session persistence
- dashboard / system summary rendering
- create team
- create tenant
- create environment
- list oauth profiles
- create oauth profile
- update oauth profile
- delete oauth profile
- list connections
- create connection
- update connection
- delete connection
- update environment policy
- create configuration version
- activate configuration version
- rotate signing key
- activate next signing key
- revoke signing key
- update key store
- list users
- inspect user profile
- inspect user session inventory
- inspect user refresh-token inventory
- invite user
- issue password-reset link
- list environment audit events
- list team audit events
- filter environment/team audit events by event type and category
- export team audit events
- read audit event detail
- create client
- update client
- delete client
- issue client secret
- revoke client secret
- revoke-all client secrets
- logout

The current sibling `../aegaeon-admin-console` user-management route also exposes additional local
IAM operations through the same SDK boundary: edit/delete/restore users, suspend/restore users,
inspect credential state, invite users, bulk-import users from CSV, issue activation links,
revoke password credentials, revoke recovery tokens, inspect grants, selectively revoke grants,
and selectively revoke refresh tokens. Those remain control-plane operations only; end-user
credential submission stays on the server-handled issuer/auth surface.

Follow-on product postures are tracked separately:

- Primary-authority local end-user behaviour is specified in
  `../specs/primary-authority-user-management.md`.
- Upstream-authority broker / downstream-IdP behaviour is specified in
  `../specs/oidc-rp-brokering-spec.md`.

The compose-backed browser lane now also exercises environment/team audit reads, query-string-backed
audit filtering, environment/team-audit JSON/CSV export, and audit-event detail. The sibling
`../aegaeon-admin-console` repository now also carries a hosted `Admin Console Stack E2E / Stack E2E`
workflow that checks out sibling `aegaeon` and `aegaeon-sdk` repositories, runs the same stack
lane on GitHub-hosted infrastructure, and uploads `.artifacts/admin-sdk/admin-sdk-evidence.json`
plus Playwright diagnostics as artifacts. When the sibling backend or SDK repositories are private,
`../aegaeon-admin-console/.github/workflows/stack-e2e.yml` now expects
`AEGAEON_BACKEND_REPOSITORY_TOKEN` and `AEGAEON_SDK_REPOSITORY_TOKEN` so cross-repository checkout remains
fail-closed. That hosted evidence source is now also source-managed in
`../aegaeon-admin-console/spec/workflow-inventory.current.json`, while the console-side management
auth posture itself is source-managed in `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`;
both are audited fail-closed by `pnpm test:repo`.

## Frontend routing and API mapping (recommended)

This is a suggested route layout; the exact router is up to the frontend team.

### Unauthenticated

- `/login` → `POST /authentication/sessions`
- `/bootstrap` → `POST /bootstrapping/owners`

### Team and tenant selection

- `/teams` → `GET /teams`
- `/teams/:teamId/tenants` → `GET /teams/{teamId}/tenants`
- `/teams/:teamId/tenants/:tenantId/environments` → `GET /teams/{teamId}/tenants/{tenantId}/environments`

### Environment operations

- `/teams/:teamId/environments/:environmentId` → `GET /teams/{teamId}/environments/{environmentId}`
- `/teams/:teamId/environments/:environmentId/configuration-versions`
  - list → `GET /teams/{teamId}/environments/{environmentId}/configurationVersions`
  - create → `POST /teams/{teamId}/environments/{environmentId}/configurationVersions`
- `/teams/:teamId/environments/:environmentId/configuration-versions/:configurationVersionId`
  - view → `GET /teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}`
  - activate → `POST /teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}/activate`
  - archive → `POST /teams/{teamId}/environments/{environmentId}/configurationVersions/{configurationVersionId}/archive`
- `/teams/:teamId/environments/:environmentId/policies`
  - view → `GET /teams/{teamId}/environments/{environmentId}/policies`
  - edit → `PATCH /teams/{teamId}/environments/{environmentId}/policies`

## Concurrency / “base version” handling (important)

Several write operations require `baseConfigurationVersionId`.

Frontend rule:

- Always read the Environment (or list config versions) first to learn the current
  `activeConfigurationVersionId`, then pass that as `baseConfigurationVersionId`.
- For JSON write requests (`POST`, `PUT`, `PATCH`), send it in the JSON body field
  `baseConfigurationVersionId` where the endpoint requires a configuration precondition.
- For bodyless `DELETE` configuration mutations, send the same value in the
  `aegaeon-base-configuration-version-id` header. Management `DELETE` requests do not accept JSON
  request bodies.
- On `409 base_version_mismatch`, reload the Environment and show a “configuration changed”
  message (include `x-request-id` for support).

## Error handling contract

Most non-2xx responses use:

```json
{
  "errorCode": "string",
  "message": "string",
  "details": {},
  "requestId": "string"
}
```

Frontend recommendations:

- Treat `401` as “session expired” and redirect to `/login`.
- Show `requestId` in error toasts/modals to enable operator support.
- For `403`, show a “forbidden” message and keep the user on the same page.

## OpenAPI sync strategy for the frontend repo

Local development (fastest):

- Copy `generated/openapi/aegaeon-management-api.v1.json` into the frontend repo (e.g. `openapi/`),
  and generate a client from it.

To keep the contract current (recommended):

- Pin the frontend to a specific backend git commit/tag, and have CI fetch the JSON at build time.
- Alternatively, vendor the backend repo as a git submodule and read the JSON from
  `generated/openapi/`.

## Notes / current limitations

- Management sessions support Redis-backed storage via `AEGAEON_MANAGEMENT_SESSION_REDIS_URL`.
  Multi-node server startup fails closed unless this shared store is configured.
- Management cookies are always `Secure`; run local admin-console integration through HTTPS or a
  TLS-terminating development proxy rather than disabling cookie security.
