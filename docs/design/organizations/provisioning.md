# Organizations Provisioning and Reconciliation

Last updated: 2026-10-30

Status: active plan

Owner: Engineering / Verification

Audience: implementers, operators, security reviewers

## Contract and scope

This increment refines ORG-R01/R03/R05/R15/R16/R20/R21, ORG-G01/G03/G11/G14
and ORG-P01/P03/P06/P10/P12/P13. It adds authenticated operator creation,
bounded reconciliation and restrictive lifecycle operations. The first
administrator invitation and acceptance are a separate required increment;
creation alone never grants membership or activates an organization.

All routes below are under
`/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}`.
Path object identifiers are plain UUIDs. An external identifier is an exact
UTF-8 value in the payload, without a type prefix, UUID interpretation, case
folding or Unicode normalization. Existing identifiers are preserved.

| Method and suffix | Exact capability | Input and result |
| --- | --- | --- |
| `POST /organizations` | `provision` | `externalId`, `reason`; returns a new provisioning object and strong ETag |
| `GET /organizations` | `reconcile` | `pageSize`, `pageToken`; returns retained objects including deleted ones |
| `GET /organizations/{organization}` | `reconcile` | Exact scoped object and strong ETag |
| `POST /organizations/{organization}/suspend` | `provision` | `reason`, exact object If-Match; only active to suspended |
| `POST /organizations/{organization}/delete` | `provision` | `reason`, exact object If-Match; irreversible tombstone from any nondeleted state |

No operator activation or membership creation endpoint is provided by this
increment. First activation must follow authenticated recipient acceptance.
Restoration requires its own specified authority and epoch checks. Provision
does not imply reconcile, and configure or Team ownership implies neither.

## Authorization, transactions and replay

Use the existing interactive management session, CSRF/origin validation, strict
JSON and bounded admission. Recheck the active human, Team/Tenant/Environment,
enabled domain and exact persisted operator capability in the transaction
before object lookup, precondition comparison or receipt disclosure. Recheck
the management session before commit. Unknown and foreign object IDs return the
same forbidden response after scoped authorization. Reads cannot carry a body.

Mutations require an idempotency key and nonblank reason. The canonical receipt
digest binds operation, scope through its key, actor, exact external identifier
or object/revision/state and reason. Authorized same-command retries return the
original object; changed commands conflict. A stale lifecycle revision returns
412. An existing external ID, including a tombstone, conflicts; it is never
renamed or reassigned. Serialize with the domain lock, then object lock.
Object mutation, event, outbox and receipt commit atomically. Storage failures
refuse and roll back; a lost response after commit is retried with the same key.
The receipt is not reusable authorization after grant or session revocation.

## Finite limits and deletion availability

Retain at most 1,024 organization identities per domain, counting provisioning,
suspended and deleted records. Never delete history to replenish this quota.
Operator organization creation/lifecycle receipts have a separate 10,000
ordinary-operation budget, followed by at most 2,048 restrictive operations.
Only a genuine active-to-suspended or nondeleted-to-deleted transition can use
that reserve. At exhaustion, creation and any activation/restoration are
refused. With no new creation/reactivation, each retained organization can be
suspended at most once and deleted at most once. Replays allocate nothing.
Use the separate restrictive HTTP admission class for suspend/delete. This
does not claim a budget for the still-unmounted invitation/member APIs.

Every successful operation allocates one event and one outbox entry in its
transaction. The receipt bound therefore also bounds this increment's new
events/outbox; existing configuration has its separate bound. A full aggregate
retention/export policy remains a required delivery condition. Neither bounded
storage nor an outbox row proves successful external delivery.

List pages use default 50, maximum 100, ordered by immutable UUID, stopping
before 60 KiB of object payload. Fetch at most
page size plus one rows with a scope predicate and index. A canonical bounded
cursor binds collection, Environment, domain and last UUID; it is not a bearer
credential or snapshot guarantee. Each page rechecks current authority. New
concurrent objects may require a fresh traversal. Responses use the management
camelCase representation (`id`, `environmentId`, `domainId`, `externalId`,
`state`, `revision`) and no-store headers. Grant generations remain internal.
The encoded response remains within the existing 65,536-byte limit.

## Required evidence

Exercise mounted routes with actual PostgreSQL and authenticated session/CSRF:
normal create/read/list/delete, exact UTF-8 preservation, same external ID in
different domains, case/Unicode distinctions, stale ETags, revoked actor replay,
foreign scope, deleted ID reuse, receipt conflicts, concurrent same-key create,
transaction rollback on outbox failure and ordinary quota exhaustion with
reserved deletion. Keep negative controls demonstrating missing current
authorization and exhausted-budget refusal. Bind source, schema, artifact and
suppliers to the evidence. Successful tests do not discharge a composite proof
unit or establish shipment.
