# Initialize the management plane

Last updated: 2026-09-10

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Empty database workflow

Run `aegaeon-management-init` before starting the server, against a dedicated empty
database with the repository migrations applied. Access to that database authorizes
this operator command. It atomically creates a human owner, an OWNER membership,
the initial team and tenant, the control-plane policy, and an active Environment.

Apply the matching migration inventory with revision metadata in `public` (or the
connection's current schema). A revision table in an unrelated schema is rejected
by the server's schema preflight.

```sh
DATABASE_URL="$AEGAEON_DATABASE_URL" atlas migrate apply --env local \
  --revisions-schema public
```

Provide a JSON document on standard input from a secret manager or a protected
file. Do not put the password in command arguments, shell history, or logs.

```json
{
  "ownerEmail": "owner@example.com",
  "ownerPassword": "<operator-supplied strong password>",
  "allowedOrigins": ["https://admin.example.test"],
  "issuerBaseDomain": "example.test"
}
```

```sh
aegaeon-management-init < /secure/path/initialization.json
```

The command uses the documented database connection configuration, including
`AEGAEON_DATABASE_URL`. Input is limited to 16 KiB. Unknown and duplicate JSON
fields are rejected. The owner password uses the same validation and Argon2 hash
as first-owner management bootstrap; output contains only identifiers and the
issuer host. Remove the input file from the working machine after arranging
appropriate credential storage.

The initial topology is team `primary`, tenant `primary` in region `local`, and
Environment `dev`. Its issuer is `https://dev.primary.local.<issuerBaseDomain>`.
Subsequent tenants and environments are created through the normal management API.
The command does not create OAuth clients, API keys, or signing keys. OIDC and JWT
access tokens remain disabled until the operator configures the Environment and
its keys through authenticated management operations.

Start the server using the returned issuer host as `AEGAEON_RUNTIME_ISSUER_HOST`
and the other required shared-store and TLS settings in the
[server environment reference](../configurations/environment/README.md).
Management reads allowed Origins and issuer base domain from PostgreSQL. This
command does not restore the removed environment-variable policy overrides.

For local tests, map DNS aliases to the test server and provision matching trusted
HTTPS certificates. A literal `localhost`, loopback IP, or HTTP Origin is rejected
by the existing management Origin validator. Include the actual browser origin,
including a non-default port where applicable.

Prime the CSRF cookie with `GET /api/v1/system/health`, then sign in at
`POST /api/v1/authentication/sessions` using the supplied owner credentials.
Send the registered `Origin`, the CSRF cookie, and its `X-CSRF-Token` on writes.
The resulting session can create a second Environment with
`POST /api/v1/teams/{teamId}/tenants/{tenantId}/environments` using `name` and `slug`.
See the [admin console handoff](../development/admin-console-handoff.md).

## Browser integration boundary

The tests for this initialization utility exercise the CLI and management HTTP
API. A browser console requires separate integration verification. The CSRF
cookie is host-only with `Path=/api/v1`. A UI on another host cannot read that
cookie, and a page at `/` cannot read the API-path cookie through
`document.cookie`. An Origin allowlist entry and CORS do not change these browser
rules. Configure and test an appropriate same-origin console route or an explicit
server-mediated CSRF delivery contract before claiming browser login works.

## Repetition, concurrency, and recovery

Any existing administrator or control-plane policy makes initialization fail.
The command never resets an owner, replaces an existing policy, or upgrades an
observability API key. Initializers share one PostgreSQL advisory transaction
lock and explicitly use READ COMMITTED isolation. Waiting callers check the
committed state after acquiring the lock. All writes, including the audit, commit
together; failure rolls back the complete operation.

A lost success response may leave a fully initialized database. Inspect the
non-secret identifiers and sign in with the original credentials; do not rerun
with different credentials expecting a reset. If initialization returns an error
before commit, retry after resolving the cause. Do not automatically drop a
database or delete administrators as recovery.

`aegaeon-observability-seed` is an audit-only smoke-test fixture with unusable human
credentials. Use a separate fresh database for interactive management testing.
`aegaeon-hosted-bootstrap` provisions KMS-backed hosted topology and is a separate
operator workflow.

## Evidence boundary

`Management.Initialization` models atomic initialization and environment isolation
under serialized fresh reads. It does not mechanically prove Rust, SQL, JSON
parsing, password hashing, or PostgreSQL correspondence. PostgreSQL/router tests
exercise login, Origin and CSRF enforcement, second-environment creation, replay,
racing callers, rollback, and preservation of the audit-only seed capability.
