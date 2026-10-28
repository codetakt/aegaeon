# Attribute mapping

Last updated: 2026-10-13

Status: draft

Status note: local attributes and ordinary OIDC implementation candidate; ownership integration and external capture remain open.

Owner: Server maintainers

Audience: operators, API implementers, reviewers

## Boundaries

A mapping evaluates attributes belonging to an already resolved environment and
immutable local user UUID. It cannot choose an account, link identities, assign a
subject, authenticate a provider, grant application authority, or sign a token.
`sub`, token identity/security claims, and aggregated/distributed-claim metadata
remain protocol-owned. LTI launch validation and protocol-owned LTI claims require
a separate adapter; there is no LTI adapter in this change.

The pure `aegaeon-attribute-mapping` crate accepts a trusted input snapshot and
returns values with their source evidence. Deserializing a snapshot authenticates
nothing. A source must be admitted by its writer before it reaches the engine.
Every referenced attribute needs both input permission and a grant for the exact
recipient (environment, client and output surface). The output also needs an
explicit release rule. These restrictions propagate through every static input
reference, including unused alternatives and array mapping expressions.

## Local attribute management

`GET` and `PUT` on
`/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/attributes`
use the existing human management session and OWNER/ADMINISTRATOR checks. PUT also
requires the registered Origin and CSRF token. The request is a complete local
namespace replacement:

```json
{"baseRevision":0,"values":{"department":"Engineering","contact":null}}
```

`baseRevision: 0` creates the namespace. Later writes use the returned revision;
a stale revision returns 409. `{}` removes all values while retaining revision
history. Omitted attributes are missing; JSON null is a present value. A database-confirmed
absent source namespace supplies transient absence evidence for declared inputs,
so optional claims can be omitted. It creates no source row or provider assertion. The
server records the administrator, observation time and new source revision.
The caller cannot supply external provenance, recipient permissions or another
source namespace. Audit events contain attribute names and revisions, not values.
Deleted users and revoked management roles are checked on every mutation. Mandatory
audit failure returns HTTP 503 and rolls back the attribute replacement; other
attribute-store failures return HTTP 500.

The additive `20261014090000_user_attribute_sources.sql` migration preserves
existing profile and account-link rows. Existing `custom_claims` are not promoted
to attributes with invented source provenance. Apply the migration before running
this server version. An old server does not understand the new configuration
field; remove the configuration through a reviewed transition before a rollback,
and retain the additive table and its data.

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

## Remaining integration obligations

Any production OIDC output must join permanent issuer/subject ownership before
using the subject to resolve a local owner. External provider capture additionally
requires authenticated issuer/subject resolution, account-link review and migration
before writing attributes. These remain release conditions for this candidate. Legacy links and previously issued derived state need their own
reviewed transition. This candidate does not discharge those obligations or
establish a complete federation mapping feature. It also does not establish LTI
conformance or formal product assurance.
