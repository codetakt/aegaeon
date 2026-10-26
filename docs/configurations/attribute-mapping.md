# Attribute mapping and local user attributes

Last updated: 2026-10-13

Status: current implementation baseline

Owner: Server maintainers

Audience: operators, API implementers, reviewers

## Available functionality

Aegaeon provides a [common transformation engine](../../crates/attribute-mapping/README.md)
and a management API for structured local user attributes. Stored attributes are
owned by an immutable environment/user UUID pair. They are separate from the
existing user profile and its `custom_claims`.

The engine supports typed structured transformations, source provenance and
explicit recipient restrictions. Its caller supplies authenticated input and a
versioned policy with an adapter-owned output contract. This server version does
not register an output adapter or accept an `attributeMapping` configuration
field at the document root. The existing federation mapping configuration is
unchanged. Managing local attributes does not change ID Token, UserInfo or access
token output, and does not create recipient disclosure grants.

## Management API

`GET` and `PUT` on
`/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/attributes`
require a human management session with the team's OWNER or ADMINISTRATOR role.
The server rechecks that role and the user's ownership inside the transaction.
PUT also requires the registered Origin and CSRF token through the existing
management middleware. Deleted users are not readable or writable here.

PUT replaces the complete local namespace:

```json
{"baseRevision":0,"values":{"department":"Engineering","contact":null}}
```

`baseRevision: 0` creates an absent local namespace. Each successful write
increments the revision; later writes must provide the current revision. A stale
revision returns 409 with `currentRevision`. Concurrent writes with the same
base revision cannot both succeed. Writing `{}` removes all values while
retaining the source row and revision, so a stale creation cannot recreate an
old revision. An omitted member is missing; JSON null is a present value.

GET returns `userId` and a `sources` array. An uninitialized local namespace
produces an empty array. PUT returns `userId` and the replaced `source`. Source
records contain `namespace`, `revision`, `values` and `provenance`; provenance
contains `kind`, `authority`, `source_revision`, `observed_at` and `expires_at`.
Local writes use the authenticated administrator as authority, the source
revision as provenance revision, the database observation time and no expiry.
Request bodies cannot choose a different source namespace or supply provenance.

Each write and its audit event commit in one transaction. Audit data records
the source, previous/new revision and attribute names, without copying attribute
values. A mandatory audit failure returns 503 and rolls back the replacement.
Use stable schema names rather than putting confidential values in keys.

Values must be a JSON object of at most 256 KiB when encoded. Attribute names
must be nonempty, have no leading/trailing whitespace or control characters,
and fit within 512 bytes. JSON depth and collection sizes follow the common
engine limits. Invalid input, a stale revision, a missing owner or a database
failure returns an error without a partial write. Database reads reject source
sets exceeding 1 MiB of encoded database JSON or 1,024 source records.

## Storage and upgrades

Apply `20261014090000_user_attribute_sources.sql` before starting this server
version. It adds `aegaeon.user_attribute_sources` and composite ownership keys.
The environment/user key prevents cross-environment ownership; a reserved
external namespace is structurally bound to its environment/connection key.
Only local writes are implemented. External provider ingestion, expiry and
retirement require a separate authenticated writer and account-link contract.

The migration does not modify existing profile or account-link values and does
not infer provenance or disclosure permissions for legacy `custom_claims`.
Rollbacks to an older server retain the additive table and its data. Older
servers ignore these attributes; they cannot manage or publish them.

This change does not install a dedicated restricted runtime role. Deployments
must apply the same management database authority used by existing user APIs.
Any later runtime-role restriction must include the new table in its reviewed
permission set without granting protocol readers management write access.

## Integration boundary

Before publishing mapped attributes through a protocol, its adapter must bind
the authenticated subject to the immutable local owner, authenticate source
metadata, select the actual recipient, authorize the policy, preserve source
restrictions and enforce the protocol-owned output contract. Permanent subject
ownership and account-link migration remain separate integration work.

The local API and transformation engine do not establish complete federation
mapping or LTI support. Their finite unit and PostgreSQL tests do not establish
formal product assurance.
