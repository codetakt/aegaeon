# Organizations Member API

Last updated: 2026-10-30

Status: active plan

Owner: Engineering / Verification

Audience: implementers, security reviewers, client integrators

## Contract and scope

This refines ORG-R01/R02/R05/R06/R08/R11/R15/R16/R20/R21, ORG-G03/G08/G09/G11/G14
and ORG-P01/P02/P03/P04/P05/P06/P10/P12/P13/P14. It supplies the delegated member
consumer required by invitations. It does not enable public configuration or
establish complete Organizations conformance.

Use the exact `{issuer}/organizations` resource audience and an explicitly
configured management target. The resource-server DPoP authentication, original
root ceiling, selected token, current primary authority, transport and finite
worker/connection rules in [own-resource.md](own-resource.md) apply. A management
console session, platform role or ordinary Bearer token cannot substitute.

## Requests and representations

| Method | Path | Required selected privilege |
| --- | --- | --- |
| GET/HEAD | `/organizations/{organization}/members` | `organization.members.read` |
| GET/HEAD | `/organizations/{organization}/members/{user}` | `organization.members.read` |
| PUT | `/organizations/{organization}/members/{user}` | `organization.members.manage` |

Path identifiers are ordinary UUIDs. `organization` is the retained organization
object ID; `user` is the permanent Environment-scoped end-user object UUID.
The organization/user pair identifies the membership relation through separate
path segments. The external organization identifier stays opaque and is returned
unchanged. No object-kind prefix is embedded in an ID. Membership output contains
`organizationId`, `organizationIdentifier`, `userId`, `incarnation`, `state`,
`roles` and `revision`; it omits
email, names, credentials and other profile data. An individual representation
has the existing strong `"<incarnation UUID>.<revision>"` ETag. The incarnation is a retained
authority-generation marker, not a separate lookup key; the primary member
identity remains the organization/user pair.

The list accepts only unique `limit` (default 50, maximum 100) and `after` query
parameters. Its canonical bounded cursor binds Environment, domain,
organization, acting user, client registration and the last user UUID.
The cursor is pagination state, never authority; all requests authenticate and
check current permission. Changing any bound context refuses it. Order by
user UUID and return a `members` array plus `nextCursor`; each page fits
64 KiB. Pagination observes current state and is not a consistent export.

Read requests have no body. PUT has no query and requires a single
`application/json` body, the exact strong `If-Match`, and an `Idempotency-Key`.
Use existing strict JSON decoding: unknown or duplicate fields refuse. Its
camelCase body contains `state` (`active`, `suspended` or `removed`), unique role
keys (at most 64) and a nonblank bounded `reason`. The response is the resulting
membership and ETag. Bodies fit 64 KiB and have the existing ten-second read
deadline. Secrets never enter path, query, receipt, audit or logs.

## Authority and transitions

Before disclosing an object or testing a stored precondition, require the
authenticated selected organization's object ID to match the path. Lock and
revalidate primary Environment/domain/client/target, original approval, actor
identity, membership and role versions in the same transaction as the read or
mutation. Derive actor/client/root/key from authenticated server metadata.
Request fields cannot provide authority. A foreign or inaccessible identifier
has one generic refusal; no existence probe is provided.

PUT also requires an effective membership-management role and checks assignable
roles for both removed and added roles. Its current role definitions must match
the captured original authorization. Recheck current actor authority before a
receipt lookup, including retries. The mutation locks the domain and organization
before member state and serializes the last-effective-administrator check.

This route changes an existing membership; it cannot create one, accept an
invitation, or reactivate an invited/removed incarnation. A separately authorized
explicit update can reactivate a suspended membership only while the global
identity is active, and must advance the grant generation. An invitation cannot
use this path to revive a suspended member. Removing roles or suspending a member
cannot remove the last effective administrator. Global identity security
suspension remains independent and must still succeed.

The native command receipt binds actor, immutable client registration, scope,
operation, idempotency key and canonical request. Matching retries return the
recorded result without applying the mutation again; changed payloads conflict.
A later current GET determines current state. Retained member incarnation IDs
are never reused. Audit and protected outbox commit with the state and receipt.
Any storage failure rolls back all effects. Check the active runtime projection
again before commit and use shared commit admission; a prior cleanup closure
refuses publication.

The owned request worker may complete after a caller disconnects or its response
deadline expires. It retains admission and transaction ownership. The client
retries with the same request/key or reads current state; it must not assume a
lost response means rollback. This is not a finite outage-recovery promise.

## Finite budgets and errors

Use the shared four ordinary request owners and existing database deadlines.
Retain at most 10,000 member-command receipts per domain for ordinary updates.
Reserve 20,000 additional receipts exclusively for actual monotonic reductions:
active-to-suspended/removed or suspended-to-removed, without adding roles.
Repeated no-op requests cannot consume this reserve. At most 10,000 retained
membership identities per domain may be created by the native command path;
tombstones count toward this bound. Invitation issuance/acceptance must share
that creation bound before they are connected. Exhaustion fails closed and
requires explicit export/retention operations; runtime code never deletes
authority history to recover space.

Use the resource's no-cache OAuth errors: malformed request 400, invalid token
401, missing authority 403, missing precondition 428, stale precondition 412,
changed receipt or capacity conflict 409, and unavailable storage/runtime 503.
DPoP challenges retain their existing verifier semantics. No error returns
private membership or credential details.

## Required validation

Exercise real original authorization and Token Exchange, mounted resource
routes, resource DPoP, current SQL state and receipt/audit/outbox effects. Cover
normal listing/update, cross-scope and cross-organization paths/cursors, missing
privilege, role escalation/removal, old token after role widening, revoked actor
and root, duplicate input, stale ETags, replay, concurrent updates, last-admin
protection, cancelled responses, receipt exhaustion, store failure and recovery.
Retain a negative control removing an actual authorization/currentness guard.
All results stay bound to their exact compiled source and suppliers; passing
tests do not discharge the full composite proof obligations.
