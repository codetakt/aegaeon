# Organization audit history

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: Implementers and operators

## Scope

This successor concretizes ORG-R16/R20, ORG-G03/G11 and ORG-P06/P10/P12.
It does not change the adopted export/import/restore requirements. Audit API
completion is distinct from consistent snapshot export and archival delivery.

## Read authority and API

GET/HEAD /api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/audit-events
requires a current interactive human management session and an explicit current
Export capability for that exact domain. Ownership, Configure, Provision,
Reconcile and Support do not imply Export. Every page rechecks current authority.
An unauthorized principal gets the same refusal for present and absent domains.

The query accepts only pageSize (1..100, default 50) and pageToken. The opaque
canonical cursor is versioned and bound to Environment/domain and audit kind.
Order is immutable event UUID; this is a live traversal, not a consistent backup.
Concurrent new UUIDs before a prior cursor may not be seen. Complete migration
export must use its separately defined snapshot mechanism.

Each response contains immutable event ID, Environment/domain/optional organization
UUID, actor kind/internal UUID/client registration, request ID, reason, event type,
recorded timestamp and bounded structured event data. Original record identities
are preserved; no UUID resource-kind prefix is added. The reader never loads
passwords, token stores, invitation capabilities, recipient challenges or private
authorization snapshots. Audit producers own their minimal event schemas.

The response is no-store, at most 64 KiB. A page may contain fewer than the requested
number of events; its next cursor follows the final returned event. A single
unsupported oversized event refuses with 503 and is never silently skipped.
The ordinary finite admission budget and 30-second deadline apply; there is no
background scan, unbounded fetch or store failure fallback. Domain and operator
locks serialize disclosure against mutation; the session is checked again before
commit/response. HEAD uses the same authorization and validation.

## Retention boundary

This first endpoint is read-only. It adds no deletion, expiry or acknowledgment
mutation. Existing permanent authority receipts and ownership tombstones remain
unchanged. In-product archive/retention and at-least-once outbox consumption must
be specified and implemented with snapshot completeness and deduplication before
ORG-R16/R17 or Organizations shipment can be declared complete. A successful page
read is not an archival acknowledgment, a guarantee of delivery or proof discharge.
