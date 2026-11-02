# Attribute mapping and local user attributes

Last updated: 2026-11-02

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
versioned policy with an adapter-owned output contract. An activated root
`attributeMapping` field opts ordinary ID Token and UserInfo output into the OIDC
adapter described below. Without that field, the existing profile/custom-claim
path remains active. With the field, a missing recipient policy releases no
supplementary claims and does not fall back to legacy disclosure. Attribute writes
alone create no disclosure grant; access-token and federation mapping behavior
is unchanged.

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
the source, previous/new revision and a prefix of attribute names, without copying
attribute values. `attributeNames` contains at most 32 names and 1,024 encoded JSON
bytes (including escaping and array punctuation). `attributeNameCount` records
the total and `omittedAttributeNameCount` explicitly records omitted names.
A mandatory audit failure returns 503 and rolls back the replacement.
Use stable schema names rather than putting confidential values in keys.

Values must be a JSON object of at most 256 KiB when encoded. Attribute names
must be nonempty, have no leading/trailing whitespace or control characters,
and fit within 512 bytes. JSON depth and collection sizes follow the common
engine limits. Invalid input, a stale revision, a missing owner or a database
failure returns an error without a partial write. Database reads reject source
sets exceeding 1 MiB of encoded database JSON or 1,024 source records.
Writes check this aggregate database representation under the owner lock before
replacement, including PostgreSQL's expanded numeric spelling. NUL characters
in strings or object keys at any depth are invalid because PostgreSQL JSONB
cannot store them. Neither rejection changes the revision or stored values.

Numeric values use the server's JSON number model: signed/unsigned 64-bit integers
and finite IEEE 754 binary64 values. Decimal/exponent inputs use binary64 precision;
this is not an arbitrary-precision decimal or original-JSON-text storage API.
The parser preserves binary64 values on serialization and database readback.
Represent exact decimal quantities and large identifiers as strings when their
precision must survive clients with narrower number models. JavaScript SDK callers
must keep integer revisions within `Number.MAX_SAFE_INTEGER`; larger revisions are
rejected before sending a write. See [RFC 8259 Section 6](https://www.rfc-editor.org/rfc/rfc8259.html#section-6).

GET uses shared row locks for the current human role, team, tenant, environment
and user, permitting concurrent readers while preventing lifecycle changes
during the read. If PUT supplies `If-Match`, the current GET representation is
checked inside the write transaction; a stale tag returns 412. The required
`baseRevision` still applies, including when `If-Match` is omitted or `*`.
All `If-Match` field lines are evaluated as one entity-tag list, using strong
comparison. Quoted commas are part of a tag; weak tags do not match. Malformed
lists, including a wildcard mixed with tags, fail with 412 before mutation.
See [RFC 9110 Section 13.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match).
The GET response documents its strong `ETag`. Management CORS permits `If-Match`
and exposes `ETag` to explicitly allowed origins; Origin, CSRF and human-role
checks still apply to writes.

## Storage and upgrades

Apply `20261101090000_user_attribute_sources.sql` before starting this server
version. It adds `aegaeon.user_attribute_sources` and composite ownership keys.
It follows the complete subject-ownership migration sequence and replaces the
physical-catalog checker to include the new key and exact migration inventory.
Stop and drain all server instances before applying it, then deploy the matching
server build; the previous build deliberately rejects the newer catalog.
Existing main migrations and their checksums remain unchanged.
The environment/user key prevents cross-environment ownership; a reserved
external namespace is structurally bound to its environment/connection key.
Physical deletion of a user cascades to its attribute sources, including empty
namespaces. Permanent UUID ownership and subject reservations remain intact;
attribute cleanup does not permit identity or subject reuse.
Only local writes are implemented. External provider ingestion, expiry and
retirement require a separate authenticated writer and account-link contract.

The migration does not modify existing profile or account-link values and does
not infer provenance or disclosure permissions for legacy `custom_claims`.
Retain the additive table and its data on rollback. A binary-only rollback to
the previous version cannot serve this catalog: its compiled preflight rejects
the new schema. Use a compatible build until a catalog rollback procedure has
been reviewed and validated; dropping the attribute table is not that procedure.

This change does not install a dedicated restricted runtime role. Deployments
must apply the same management database authority used by existing user APIs.
Grant `SELECT`, `INSERT` and `UPDATE` on `aegaeon.user_attribute_sources` only
to the configured management database login. The API does not require `DELETE`,
DDL or subject-maintenance authority. Protocol mapping uses a read-only repeatable-read transaction. A deployment that
separates management writers and protocol readers must give the latter only
attribute SELECT authority; SQL transaction mode does not remove privileges from
a shared login. Credential separation remains a supplier qualification condition.

## Versioned configuration

Add `attributeMapping` to the existing environment configuration document. Use the
normal create-version and activation APIs, authorization, audit and runtime reload
mechanisms. The example below is the value of that field, not a complete document:

```json
{
  "schemaVersion": 1,
  "sources": [{
    "namespace": "local",
    "kind": "local",
    "attributes": [{
      "name": "department",
      "recipients": [{"clientId":"example-rp","surface":{"kind":"userinfo"}}]
    }]
  }],
  "policies": [{
    "recipient": {"clientId":"example-rp","surface":{"kind":"userinfo"}},
    "inputs": [{"source":"local","name":"department"}],
    "outputs": {
      "organization": {
        "op":"object",
        "fields": {
          "department":{"op":"read","attribute":{"source":"local","name":"department"},"path":[]}
        }
      }
    },
    "releasedOutputs": ["organization"],
    "customSchema": {
      "organization":{"required":true,"schema":{"type":"object","properties":{
        "department":{"required":true,"schema":{"type":"string"}}
      }}}
    },
    "requiredScopes": ["openid","profile"]
  }]
}
```

Sources, recipients and input references are checked at admission and runtime
load. Unknown configuration fields, duplicate selectors, protected output names,
and attempts to replace standard OIDC schemas are rejected. The actual
configuration version and fingerprint bind authorization evaluation; a caller's
label cannot substitute for that authority.

With the field absent, existing profile behavior remains in effect. With the
field present, supplementary claims come exclusively from mapping. A recipient
without a policy receives no mapped attributes; it does not fall back to legacy
custom claims. An empty `policies` array therefore denies supplementary output.
Removing the field restores legacy behavior and must be reviewed as a disclosure
change. No new permission is implied by adding a transformation rule.

## Expressions and output

Supported operations are exact-path reads, constants, objects, arrays, coalesce,
ASCII lowercase, concatenation and array item mapping. Paths explicitly distinguish
object keys from array indices. No operation performs IO or executes arbitrary
code. Missing object members are omitted; a missing array item fails evaluation
rather than shifting positions. Coalesce selects a present value, including null.
Custom schemas describe strings, booleans, numbers, integers, null, arrays and
objects; unknown object members and incompatible output types are rejected.

Standard OIDC claim types and scope eligibility belong to the OIDC adapter. The
standard voluntary claims may be absent. `email_verified` and
`phone_number_verified` cannot be manufactured with a true literal or arbitrary
local Boolean. A configured external verification flag must be a direct read
alongside the unchanged corresponding value from the same source. External
source persistence is not implemented by this candidate; its authenticated
callback and account-ownership integration remain required.

The engine bounds input bytes, output bytes, collection sizes, expression depth,
node count and evaluation steps. Configuration JSON is limited to 256 KiB; local
attribute values to 256 KiB; selected engine inputs including metadata to 256 KiB;
engine output to 64 KiB. Exceeding a bound or encountering an invalid permission,
type or expiry fails the operation without partial output. Stored source sets exceeding 1 MiB of database JSON are rejected before
transferring their values from the database.

## OIDC observation times

Authorization evaluates for the admitted Client ID and selected scopes. It stores
the mapping result with the authorization code. ID Token issuance rechecks issuer,
subject, client, surface, scopes and source expiry before adding the mapped claims
to the normal signed token. Existing code lifetime and invalidation rules apply;
a configuration update does not rewrite an already captured result.

UserInfo uses the Client ID from validated access-token metadata, independently
of the resource audience. It reads active configuration, local owner and attribute
sources in one repeatable-read transaction. It evaluates the current policy and
current values. A policy with unmet required scopes releases no supplementary
claims. Ordinary standard-claim scope filtering still applies inside the adapter.

The scope-to-claim groups and verification-flag semantics follow
[OIDC Core sections 5.1 and 5.4](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
Mapping does not introduce support for the optional `claims` request parameter.

## Integration and assurance boundary

The complete encoded mapping snapshot, including issuer, subject and scopes, must
fit 65,536 bytes before code issuance and again before output. Boundary regressions
cover exact-size success and one-byte overflow for both OIDC surfaces.

The OIDC adapter resolves the authenticated issuer/subject through the current
Environment, active local user and matching permanent namespace inside the same
read-only database snapshot as configuration and source values. A missing namespace
refuses mapping. Permanent UUID ownership and subject reservations are enforced by
the namespace factory's checked catalog and protected end-user write constraints;
the protocol reader cannot SELECT the private owner maps. Privileged changes require
complete runtime drain and revalidation. The adapter never creates an identity.
The surrounding protocol namespace admission and token/session validation remain
required; a successful database query alone does not authenticate a caller.

Task1b retains external provider capture, authenticated account-link resolution,
source expiry/retirement, legacy-data transition and actual reader/writer credential
separation. These are not implemented by the local-to-OIDC adapter. Fix adapter
identity, recipient, revision, storage and protocol defects here rather than relying
on a later assurance review to repair them. The finite tests cover this adapter and
existing local APIs; they do not establish complete federation mapping. Current
integration validation covers 16 restricted-PostgreSQL attribute cases, five mapping
unit cases, four ID Token cases and eight UserInfo cases. The namespace fault test
also runs the predecessor SQL lookup and demonstrates its incorrect acceptance.
CI must repeat the selected checks on the exact published integration revision.

Task3 must bind the actual configuration version, immutable owner, source authority,
recipient, scopes, observation time, code snapshot, UserInfo read and released
binary to the adopted mapping claims. Preserve all original whole-domain, caller,
store, supplier, resource and recovery conditions. New formal discharge is zero.
LTI Core 1.3 is a separate adopted assurance protocol. Its Platform adapter must
apply the LTI output contract and launch authorization; ordinary OIDC mapping does
not establish LTI conformance or certification.

## Management SDK reference

`getUserAttributes` and `replaceLocalAttributes` expose these routes through the
management client reference, retaining path escaping, session credentials, Origin
and CSRF handling. Replacement sends `baseRevision`, the complete `values` object
and an optional `ifMatch` header. `getUserAttributes` adds the HTTP response's
`etag` alongside the JSON fields (null if absent), so a caller can pass that tag
back without a separate fetch. Stale revisions and tags remain 409/412 errors.
The SDK snapshots finite, acyclic JSON data before asynchronous CSRF work. It
rejects undefined, non-finite numbers, functions, symbols, BigInt, sparse arrays,
accessors and non-JSON object types rather than silently dropping or replacing
values. Depth, collection and encoded-size limits apply to this snapshot.
This updates the reference shipped here; adoption by an external SDK distribution
requires its own artifact and release verification.
