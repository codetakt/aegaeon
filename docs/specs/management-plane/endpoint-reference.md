# Management Plane Endpoint Reference

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Management API endpoint skeleton (Phase 1)

This is a non-exhaustive Phase 1 overview, not the complete current operation
inventory. The generated OpenAPI, actual server routes and SDK exports must be
reconciled for each release under the [SDK assurance contract](../../verification/claims/sdk-assurance/assurance-contract.md).
An operation omitted here is not excluded from that contract. Generated OpenAPI
describes interfaces; it does not independently prove their correctness.

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

Client responses include `dpopBoundAccessTokens`. Create omission defaults to false;
PATCH omission preserves the current value, and an explicit boolean replaces it.
Explicit null and nonboolean values reject. A true value requires DPoP at the token
endpoint and is rejected at save time when the current effective profile selects
mTLS. A later policy change can still create a conflict, which token requests reject.
Changes are audited and enter the runtime client fingerprint. See the
[upgrade procedure](../../operations/client-dpop-minimum-upgrade.md) before deploying
to a database with existing clients.

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

## Organizations provisioning and reconciliation

Under `organization-domains/{domainId}`, the authenticated human management
API additionally provides `POST /organizations` with exact `externalId` and
`reason`, `GET /organizations` with bounded pagination, and
`GET /organizations/{organizationId}`. Object IDs are plain UUIDs; external IDs
remain exact scoped UTF-8 values. Creation requires explicit `provision` and
returns `provisioning` without membership. Reads require separate `reconcile`.
`POST /organizations/{organizationId}/suspend` and `/delete` require `provision`,
an exact strong ETag, reason and idempotency key, and use restrictive admission.
Deletion retains the identifier. No operator activation endpoint is implied.
See [provisioning limits and transaction rules](../../design/organizations/provisioning.md).

## Organizations first-administrator invitations

Within an Environment/domain, `POST /organizations/{organization}/invitations`
requires current `provision`, the organization's exact strong ETag, an idempotency
key and JSON `recipient`, unique `roles`, optional `lifetimeSeconds` and `reason`.
It only prepares an invitation for an empty provisioning organization.
`GET/HEAD /invitations/{invitation}` requires `reconcile` and returns six
secret-free fields with an ETag. `POST /invitations/{invitation}/revoke` requires
current `provision`, that invitation's ETag, an idempotency key and reason, and
uses reserved cancellation admission. All IDs in these paths are plain UUIDs.

The existing human session and mutation Origin/CSRF rules apply. Issuance and
cancellation replays recheck current authority; no capability or recipient
address appears in a response. GET/HEAD cannot accept, and issuance grants no
membership. See the [invitation flow contract](../../design/organizations/invitation-flow.md)
for deadlines, current recipient/inviter obligations and separate delivery and
recipient API integration status. No completed end-to-end invitation claim is
implied by these operator endpoints.

## Organizations role policy

`GET` and `PUT /organization-domains/{domainId}/role-policy` require the current
interactive human's explicit `configure` grant. The PUT body contains `roles`
and `reason`; each role supplies `key`, `privileges`, `managesMembers` and
`assignableRoles`. The response identifies the domain with its plain UUID and
returns the policy `revision` and each retained role's `version`.
Role keys and privileges are semantic vocabulary; they are not object identifiers.

Replacement requires the exact strong role-policy ETag and an idempotency key.
Current authority is checked before receipt replay. Existing keys cannot be
removed or renamed. Changing a definition advances only that role's version and
requires new authorization for grants that used it. The domain activation
revision and grants using only unchanged definitions remain unchanged.
The API refuses a change that removes an active organization's last effective
manager. A complete catalog is limited to 64 roles and 48 KiB encoded; ordinary
configuration receipts have a finite budget. See the
[role-policy contract](../../design/organizations/role-policy.md) for transaction,
error, concurrency and recovery boundaries.

## Organizations operator configuration

The configuration routes below require a current interactive human management
session. Mutations also require the configured Origin/CSRF checks. API keys do not
authorize these routes.
They do not issue business access tokens or implicitly grant membership.

| Method | Environment-relative path | Required authority |
| --- | --- | --- |
| POST | `organization-domains/default` | Active Team owner; explicit disabled bootstrap |
| GET | `organization-domains/{domainId}/operators` | Current `configure`; bounded pages with scope-bound cursor |
| POST | `organization-domains/{domainId}/operators` | Current domain `configure` grant |
| PATCH | `organization-domains/{domainId}/operators/{grantId}` | Current `configure` and exact `If-Match` |
| POST | `organization-domains/{domainId}/operators/{grantId}/revoke` | Current `configure` and exact `If-Match` |

All paths are beneath `/api/v1/teams/{teamId}/environments/{environmentId}`.
Object identifiers are plain UUIDs. JSON uses the existing camelCase convention.
Grant creation takes `administratorId`, `active`, `capabilities` and `reason`;
updates take `active`, `capabilities` and `reason`; bootstrap and revoke take
only `reason`. Unknown and duplicate members refuse. Successful responses are
200 with a representation and strong ETag. Every mutation requires an
`Idempotency-Key`, and retries recheck current authority before receipt lookup.

Reads accept canonical `pageSize` (1–100, default 50) and an opaque `pageToken`.
Responses contain `operators` and `pageInfo.nextPageToken`; each page checks
current human and domain authority and includes retained revoked grant identities.
Pagination is not a frozen multi-request snapshot. Nonempty read bodies, duplicate
or unknown query fields, and foreign-scope cursors refuse.

The [Organizations HTTP profile](../../design/organizations/http-boundary.md)
and [operator authority contract](../../design/organizations/operator-authority.md)
define finite input, admission, database and retention bounds, reserved revocation,
precondition errors, disabled defaults and remaining business activation conditions.

### Invitation recipient resource

The recipient API is separate from management sessions: `POST
/organization-invitations/{domain}/{invitation}/challenges` and `POST
/organization-invitations/{domain}/{invitation}/accept` require the dedicated
`{issuer}/organization-invitations` audience, `organization.invitation.accept`
scope, matching DPoP proof and an access token valid for at most 300 seconds.
Configure that target/scope in ordinary OAuth/Token Exchange policy and the
exact domain's client permission before issuing tokens. A token for UserInfo or
selected organization access cannot substitute. Object paths are plain UUIDs.

Challenge creation needs the invitation capability and `Idempotency-Key`;
acceptance needs both capabilities and the challenge UUID. Only the configured
recipient address receives the challenge. Responses omit addresses and secrets.
GET/HEAD never accept. Current identity, client, inviter and role checks apply
to retries. See [the invitation contract](../../design/organizations/invitation-flow.md)
and the generated Organizations OpenAPI. Configured delivery and signup/recovery
remain separate suppliers; these endpoint definitions do not establish release
readiness.

### Organization invitation delivery

`GET/HEAD` and `PUT` on
`/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/invitation-delivery`
read and explicitly configure the domain's fixed HTTPS delivery channel.
`POST` to its `/disable` child removes the channel through reserved cancellation
admission. These operations require current `configure` capability; mutations
also require the management session, Origin/CSRF, exact domain ETag, idempotency
key and reason. Configure takes `channel.endpoint` and `channel.credentialSha256`.
The actual credential is independently provisioned to the one-shot worker.
See [the delivery contract](../../design/organizations/invitation-delivery.md).

### Organization recovery, support policy and audit history

Under the same Team/Environment/domain base, the identity-policy GET/HEAD/PUT
and POST disable operations require a current human Team owner and explicit
configure authority. They control invitation-linked registration/recovery and
the selected new-subject UUID profile. The support-policy operations use the
same authority and a distinct strong support-policy ETag; configuring them does
not activate business support access. See [identity enrollment](../../design/organizations/identity-enrollment.md)
and [administrative access](../../design/organizations/administrative-access.md).

POST organizations/{organization}/administrator-recovery requires a current
human Team owner, explicit provision authority and no effective administrator.
It returns the organization to provisioning with a new authorization generation;
replacement administration still requires first-admin invitation acceptance.

GET/HEAD audit-events requires explicit Export authority on every page. The
no-store live listing is bounded to 100 events and 64 KiB, with a cursor bound to
Environment, domain and audit kind. Reconcile and ownership do not imply Export.
This is not a consistent migration snapshot or an archive acknowledgment; see
[the audit history contract](../../design/organizations/audit-history.md).

GET/HEAD audit-events/pending returns at most 100 undelivered immutable events
and 64 KiB with exact event digests and a strong batch ETag. POST
audit-events/acknowledgments requires current Export, interactive session,
Origin/CSRF, Idempotency-Key and exact If-Match; its body contains ordered
event ID/digest pairs and a reason. Delivery state and a permanent receipt update
atomically; current authority is checked before replay. Changed requests conflict,
stale batches fail, and an independent 602212-receipt capacity refuses new ACKs
without deleting history. Neither delivery status nor acknowledgment changes
authorization. See [durable consumption](../../design/organizations/audit-delivery.md)
for byte-level digest, retry and local receiver custody contracts.

GET snapshot streams a consistent domain snapshot as `application/x-ndjson`.
The current human session and explicit Export capability are checked on the
live primary before the header, each page and terminal manifest. HEAD performs
only the current authorization check. No query parameters or request body are
accepted. The response is no-store and excludes credential material. One export
per process has a one-hour lifetime, 30-second progress deadline, ten rows/page,
256 KiB/row, one million rows/section and 64 GiB total limit. An interrupted HTTP
200 remains incomplete: verify every section's count/hash and the terminal
manifest before retaining a completed snapshot. See
[the snapshot contract](../../design/organizations/snapshots.md) for exact framing,
dependency history and the separate import/activation requirements.
