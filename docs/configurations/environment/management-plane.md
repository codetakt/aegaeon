# Server Environment: Management Plane Settings

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This document is part of the split server environment-variable reference. Use this file for the detailed section below.

## Management plane (Admin API)

These variables control the management API served under `/api/v1/*` (control plane).

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_MANAGEMENT_ALLOWED_ORIGINS` | _removed_ | `control-plane` | Removed startup-environment fallback. Comma-separated browser origins (scheme+host+port) that are allowed to call write endpoints. In the supported server runtime, `aegaeon.control_plane_policies.management_allowed_origins` is authoritative. |
| `AEGAEON_MANAGEMENT_COOKIE_SECURE` | _removed_ | `system` | Removed legacy bootstrap override. Management cookies always include the `Secure` attribute; startup fails closed if this variable is present. |
| `AEGAEON_MANAGEMENT_ISSUER_BASE_DOMAIN` | _removed_ | `control-plane` | Removed startup-environment fallback. DNS base domain used when generating issuer hosts for new Environments (the issuer host itself is stored per Environment). In the supported server runtime, `aegaeon.control_plane_policies.management_issuer_base_domain` is authoritative. |
| `AEGAEON_MANAGEMENT_SESSION_TTL_SECS` | _removed_ | `control-plane` | Removed startup-environment fallback for management session TTL in seconds (valid range 1-86400). In the supported server runtime, `aegaeon.control_plane_policies.management_session_ttl_seconds` is authoritative. |
| `AEGAEON_MANAGEMENT_MAX_SESSIONS` | _removed_ | `control-plane` | Removed startup-environment fallback for the maximum number of concurrent management sessions retained in the selected backend (valid range 1-1000000). In the supported server runtime, `aegaeon.control_plane_policies.management_max_sessions` is authoritative. |
| `AEGAEON_MANAGEMENT_SESSION_REDIS_URL` | _unset_ | `system` | Redis URL for shared management API sessions. Required by the supported server runtime. |
| `AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL` | _unset_ | `system` | Redis URL for management login rate-limit buckets. Startup fails closed when this surface is required and the URL is unset. |
| `AEGAEON_MANAGEMENT_BOOTSTRAP_TOKEN` | _unset_ | `system` | Optional shared secret for first-owner bootstrapping. If set, `POST /api/v1/bootstrapping/owners` requires `bootstrapToken` to match. Remove/rotate after initial bootstrap. |

### Empty database initialization

Use [`aegaeon-management-init`](../../operations/management-initialization.md) before
starting an interactive management environment. It reads bounded JSON on stdin
and stores initial Origins and issuer base domain in PostgreSQL with the owner
credential and initial topology. It uses the existing database connection settings;
it does not introduce server runtime policy environment variables.

### Hosted bootstrap utility

The `aegaeon-hosted-bootstrap` utility uses these variables to create the initial hosted team,
tenant, environment, owner credential, and KMS-backed runtime key handle. They are operator
bootstrap inputs, not long-lived server runtime policy.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_HOSTED_BOOTSTRAP_ISSUER_URL` | _unset_ | `system` | Public issuer URL for the hosted Environment. Required. |
| `AEGAEON_HOSTED_BOOTSTRAP_OWNER_EMAIL` | _unset_ | `system` | Initial owner email address. Required. |
| `AEGAEON_HOSTED_BOOTSTRAP_OWNER_PASSWORD` | _unset_ | `system` | Initial owner password. Required; keep out of shell history and process logs. |
| `AEGAEON_HOSTED_BOOTSTRAP_TEAM_NAME` | `Aegaeon Hosted` | `system` | Initial team display name. |
| `AEGAEON_HOSTED_BOOTSTRAP_TEAM_SLUG` | `aegaeon-hosted` | `system` | Initial team slug. |
| `AEGAEON_HOSTED_BOOTSTRAP_TENANT_NAME` | `Primary Tenant` | `system` | Initial tenant display name. |
| `AEGAEON_HOSTED_BOOTSTRAP_TENANT_SLUG` | `primary` | `system` | Initial tenant slug. |
| `AEGAEON_HOSTED_BOOTSTRAP_TENANT_REGION` | `aws` | `system` | Tenant region label stored in management data. |
| `AEGAEON_HOSTED_BOOTSTRAP_ENVIRONMENT_NAME` | `Hosted Issuer` | `system` | Initial environment display name. |
| `AEGAEON_HOSTED_BOOTSTRAP_ENVIRONMENT_SLUG` | `issuer` | `system` | Initial environment slug. |
| `AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION` | `AWS_REGION` fallback | `system` | AWS KMS region for the hosted OIDC signing key handle. |
| `AEGAEON_HOSTED_BOOTSTRAP_KMS_KEY_ID` | _unset_ | `system` | AWS KMS key identifier/ARN for the hosted OIDC signing key handle. Required. |
| `AEGAEON_HOSTED_BOOTSTRAP_KMS_KID` | _unset_ | `system` | Public `kid` assigned to the hosted OIDC signing key. Required. |

Management client and client-secret mutation endpoints commit to PostgreSQL first. Server processes
refresh their issuer-scoped runtime OAuth/PAR client snapshot from the management database. The
runtime configuration monitor also fingerprints the active client projection; if the DB projection
changes and the node cannot resynchronize it, the process requests graceful restart and exits `78`
rather than serving stale client state. Client mutations remain fail-closed unless PostgreSQL-backed runtime client
synchronization is active.

Public Dynamic Client Registration (`POST /register` and RFC 7592
`/register/{client_id}` management) follows the same boundary. In the supported PostgreSQL-backed runtime it
persists issuer-scoped registrations to PostgreSQL, stores only a SHA-256 hash of
`registration_access_token`, stores client secrets as argon2id hashes in `client_secrets`, and
refreshes the runtime client snapshot after create/update/delete. `/register` bearer gating in
the supported PostgreSQL-backed runtime is configured through
`/api/v1/teams/{teamId}/environments/{environmentId}/dcrBearerToken`; the server stores only a
SHA-256 hash in `aegaeon.environment_dcr_bearer_tokens`, and DB changes are monitor-visible so nodes
restart instead of continuing with stale registration access policy. DCR bearer configuration
rejects empty values and bearer tokens shorter than 32 bytes; set/delete management operations emit
management audit events without recording the raw token or token hash. Multi-node DCR remains
fail-closed unless database-backed authority and runtime client synchronization are active.

## Removed administrative endpoint environment

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ADMIN_API_KEY` | _removed_ | `system` | Removed legacy `/admin/*` API-key environment variable. The supported management runtime uses PostgreSQL-backed administrator sessions and managed API keys. Startup fails closed if this variable is present. |

## Management data encryption

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_KEY_ENCRYPTION_KEY` | _unset_ | `system` | Operator bootstrap secret: Base64URL-encoded 32-byte key used for AES-256-GCM envelope encryption of stored key handles. This is intentionally not management-API policy because the server needs it to decrypt database-managed key handles at startup/runtime. Required when management/runtime `databaseEncrypted` key handles must be encrypted or decrypted. |

## AWS KMS integration boundary

Supported server runtime does not read a process-environment KMS key identifier. OIDC `awsKms`
runtime keys store the encrypted KMS key handle in PostgreSQL and store only the public region in
runtime-key provider configuration. AWS credentials are supplied by the AWS SDK credential provider
chain or host identity outside Aegaeon policy.

`AWS_REGION` is accepted only as a hosted-bootstrap fallback for
`AEGAEON_HOSTED_BOOTSTRAP_KMS_REGION` and as an evidence-harness input. The production OIDC signer
uses the region stored on the active runtime key. The legacy generic AWS KMS key-manager helper is
compiled only for `kms-aws` tests, so its legacy key-id and config-file inputs are not
part of the supported server runtime environment inventory.

### Application authorization boundaries

Editable profile attributes cannot supply reserved protocol or application authority
claims. Aegaeon rejects reserved custom claim names on write and removes them before
ID Token and UserInfo serialization, including values retained in older profiles or
grants. Claim-release allowlists do not override this boundary.

Projection activation binds authority to the active client's database UUID and, for
human subjects, the end-user UUID. Capture and online checks require those same
active records in the same environment with the same client ID and subject. Reusing
a deleted client's identifier or assigning a subject to a different user therefore
does not transfer the earlier projection. Service principals bind only to their
client UUID and cannot carry human roles.

Activation and token publication lock the projection, client and end-user rows in
that order until their transaction completes. Concurrent identity deletion or
subject changes wait for publication. Disabling an existing projection remains
possible after identity deactivation and retains its recorded identity bindings.

Updates require the current `baseRevision` and a strictly newer `sourceRevision`
from the same authority. Enabling a projection permits a resulting revision and
source revision up to `9223372036854775805` (`i64::MAX - 2`); consequently its
`baseRevision` must be at most `9223372036854775804`. The next counter value,
`9223372036854775806`, is reserved for an audited disable. Even at the last active
revision, the projection can therefore be revoked with the ordinary authenticated,
CSRF-protected management request. Terminal or overflowing inputs return
`400 invalid_request` before any projection or success-audit write. Disabling
still requires the owning authority, a current base revision and a newer source
revision; stale or replayed updates return `409 base_revision_mismatch`.

An exhausted disabled projection is a permanent tombstone. It cannot be reenabled,
deleted to restart its counters, or repaired by resetting revisions. These limits
preserve the rejection of old grants and apply to both revision counters.

Projection audit events retain the administrator as actor. Service-principal targets
use `APPLICATION_AUTHORIZATION` with a JSON tuple of environment UUID, client ID and
subject as `target_id`. Human targets use `END_USER` and the bound end-user UUID,
including revocation after subject reassignment. Legacy projections without a user
binding use the projection tuple. Audit data includes both identity bindings.

#### Upgrading existing projections

Apply migration `20260913090000_application_authorization_identities.sql` before
starting the updated server. It adds nullable identity bindings without backfilling
them: the current owner of a textual identifier cannot prove who originally received
authority. Existing projections without bindings stop supplying application claims;
tokens retaining those projections fail online and publication checks. Ordinary
OAuth grants without application projections keep their existing behavior.

Review each retained projection against its authoritative source and the intended
active client and end-user UUIDs. Reauthorize through the management application
authorization endpoint with the current `baseRevision`, the same `authority`, a
strictly newer `sourceRevision`, `enabled: true`, and an audit reason. The resulting
revision binds the current identities and records them in the audit event. Obtain a
new OAuth grant afterward; old grants do not gain the new revision's authority.
Use an audited disable request for projections that should remain revoked. Do not
repair ownership by assigning UUIDs directly in SQL or resetting revision counters.
Physical deletion clears the corresponding binding while retaining the projection
and its revision history.
