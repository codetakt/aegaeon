# Explicit management authority

Last updated: 2026-11-09

Status: draft

Owner: Operations

Audience: operators, maintainers

Status note: this runbook describes the #314 implementation candidate. Ordinary
delegated mutation APIs and their #316 transaction integration remain unfinished.

Installation inventory uses a selected management grant. Team membership, a Team
owner role, matching email addresses and end-user Organization memberships do not
grant installation authority. Existing Team and Organization management APIs keep
their existing authorization adapters.

Provision separate restricted PostgreSQL logins for the migration actor, serving
management API and deployment bootstrap operation. Before applying migration
`20261106010000`, run `scripts/operations/provision-management-authority.sql` with
`serving_role`, `migration_role`, `bootstrap_role` and `commit=true` variables. Run
it again after migration to bind the bootstrap login to the selected installation
and grant the narrow function permissions. Without `commit=true` the script rolls
back. The owner and bootstrap groups must have no elevated role attributes or
inherited parent roles. Runtime logins must not own management authority records
or inherit bootstrap authority.

Direct and indirect members of each protected group must be its selected migration
or bootstrap login, or an administrator with ADMIN-only grants on both groups from
the same superuser grantor. The latter is an existing administrative capability,
not proof of who originally created the groups; later self-granted INHERIT/SET
rows do not replace that requirement. The selected logins' members are checked
before the first grant as well. Unexpected membership aborts and rolls back the
provisioning transaction without automatically revoking existing privileges.

Serving and bootstrap logins must not administer role memberships, hold direct or
indirect membership in PostgreSQL's server file/program roles, or execute the
built-in server file-access and large-object import/export functions. This also
rejects ADMIN-only and currently non-inheritable memberships. Effective privileges
are checked through SET ROLE followed by inheritance, including PUBLIC grants.
Neither login may set `session_replication_role` or access management-authority
tables and columns directly. Within `management_authority`, each login can execute
only its own reviewed entrypoint:
`inventory_v1` for serving, and `bootstrap_v1` for deployment bootstrap.

Provisioning and each current entry recheck those restrictions. A later unsafe
grant causes admission to fail; the application does not revoke grants or prevent
the credential from using an already granted capability directly. The deployment
and database administrators remain trusted. These checks do not certify arbitrary
user-defined functions, extensions, or all host privileges as safe. Remove the
unsafe grant through the administrator before retrying the same operation.

The migration creates one random immutable installation UUID and resource identity
incarnations. It creates no management grants. Inspect the installation UUID as
the deployment administrator with `SELECT id FROM management_authority.installation`.
An existing installation requires the same explicit adoption operation as a fresh
one; no Team-owner grant is upgraded automatically.

Create a private JSON request naming that installation, an existing active
administrator UUID and its exact `HUMAN` or `SERVICE` kind. For example, replace
every placeholder with its intended value and generate fresh operation, grant and
selector UUIDs:

```json
{
  "installation_id": "<installation UUID>",
  "operation_id": "<operation UUID>",
  "grant_id": "<new grant UUID>",
  "principal_id": "<administrator UUID>",
  "principal_kind": "HUMAN",
  "adopt_installation": true,
  "use_selector": {
    "id": "<new selector UUID>",
    "mode": "current_descendants",
    "anchor_kind": "installation",
    "anchor_id": "<installation UUID>"
  },
  "use_actions": {
    "policy": "enumerated",
    "registry_version": 1,
    "actions": ["inventory.teams.read", "inventory.users.read"]
  },
  "conditions": {},
  "valid_from": "2026-11-06T00:00:00Z",
  "expires_at": "2026-12-06T00:00:00Z",
  "permanent": false,
  "label": "Installation inventory viewer"
}
```

Select the dedicated bootstrap login through libpq connection settings, such as
`PGSERVICE` and a private `PGPASSFILE`, then run:

```sh
python3 scripts/operations/bootstrap-management-authority.py \
  --request /private/grant-request.json --receipt /private/grant-receipt.json
```

The operation runs in one bounded repeatable-read transaction. The grant, initial
adoption, operation receipt and audit event commit together. Preserve the exact
request and receipt. After lost transport or uncertain completion, retry the same
request with the same IDs. Identical replay returns the original receipt; changing
the payload or caller under that operation ID is refused. Receipts are retained;
there is no reclamation protocol in this change. The bootstrap credential must not
be configured as an ordinary server credential.

`exact` covers the selected object incarnation. `current_descendants` snapshots
the selected anchor and its current descendants into indexed membership records;
preparation stops above 100,000 resources and never activates a partial selector.
`current_and_future_descendants` includes later descendants. Every read checks
current ancestry: moving out removes coverage, and moving into a snapshot selector
does not create coverage. Deleting and recreating an object with the same UUID
cannot revive an old exact or snapshot membership. The future selector has no
resource-count ceiling; each query still has a finite deadline and page bound.

The registered action IDs are `inventory.users.read`, `inventory.teams.read`,
`inventory.tenants.read`, `inventory.environments.read` and
`inventory.organizations.read`. Enumerated actions are the default. An explicit
`all_current_and_future` action policy uses an empty actions array and records
`registry_version: 1`; it is independent of future-resource selection. Unknown
action IDs are always rejected. Optional delegation selectors/actions form a
separate complete envelope. A delegated grant has one immutable parent and captured
delegation epoch, with at most eight edges. Authority edits invalidate descendants;
metadata-only edits preserve their authority. Revocation is terminal. Re-granting
uses a new UUID and does not revive children of a revoked grant.

Use an existing finite management session or Team-scoped API key to call
`GET /api/v1/installations/{installationId}/inventory/{resourceKind}?grantId={grantId}`.
Resource kinds are `users`, `teams`, `tenants`, `environments` and `organizations`.
The page limit is 1–200 (default 100). Each request selects one complete grant and
checks its entire live ancestry in the same SQL snapshot as the query. API keys
also retain their Team and READ/TEAM_ADMINISTRATION capability ceiling.

Responses contain `items` and `pageInfo` with `hasNextPage` and nullable
`endCursor`. Items expose only IDs, hierarchy IDs, names, subjects, issuer URL and
lifecycle state appropriate to that resource kind. Passwords, credentials, key
material, profiles and email addresses are excluded. Cursors bind the principal,
credential, installation, selected grant, query, limit and current grant-chain
revisions. They expire within five minutes or earlier when authentication expires.
Use the returned cursor unchanged with the same query. A stale cursor returns 400;
restart pagination with current authority. Invalid authentication returns 401,
insufficient grant authority returns 403, and store unavailability returns 503.
No cached positive authorization substitutes for the current SQL checks.

The current implementation exposes dedicated root bootstrap and read-only
inventory. Ordinary delegated issuance, edit and revoke HTTP commands still need
the final credential/grant/topology transaction protocol in #316; this change does
not expose direct grant-table writes to runtime roles. Retained SQL trigger and
lineage tests exercise those lifecycle constraints through explicit test-admin
fixtures. Migration, provider deployment qualification and formal assurance remain
separate obligations.
