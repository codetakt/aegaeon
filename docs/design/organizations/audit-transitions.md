# Audit transition provenance

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: Implementers and security reviewers

## Required correspondence

This implements the audit part of ORG-R16, ORG-G13 and ORG-P06/P10/P14.
Existing immutable events are retained exactly; improvements apply to new events.
Every mutation must record its actual actor/client, request identity, applicable
authority basis, and before/after version identifiers in the same transaction.
An event is historical evidence and never supplies authorization.

For organization and membership transitions, new `before` and `after` fields
identify state, revision and grant generation; memberships also identify their
permanent incarnation. Creation has a null `before`. Capture the old locked row
before mutation rather than reconstructing its generation from the new row.
Existing payload fields remain available. Recovery uses the same contract.

Authority provenance must come from the successful current authorization check.
For delivery and pre-login identity actions, the legacy actor/client columns
retain the originating invitation principal, not an assertion that it performed
the background or browser action. `authorityBasis.executor` identifies the actual
service and durable attempt, invitation capability holder (no asserted user), or
recipient identity proof and resulting user. `originatingPrincipal` explicitly
retains its separate provenance. The event request ID is the current browser
request or the stable `delivery:<object UUID>:<attempt>` correlation. No raw
capability, credential, recipient address or transport secret is included.

Domain operations record the operator grant UUID/revision and required capability;
delegated changes record the original root and the exact membership/role versions;
invitation acceptance records the invitation/version and recipient authority as
well as the retained inviter authority. A recipient action must use its current
request ID, not silently reuse the invitation creator's request ID. A background
transport result identifies its admitted attempt and does not claim fresh human
authorization. Administrative grants retain their separate authority basis.

## Validation and remaining work

Exercise creation, suspension, removal, recovery, invitation acceptance,
configuration and administrative transitions against persisted before/after
rows. Preserve replay deduplication and rollback if event insertion fails. Test
that logs contain no raw token, invitation capability or password material.
Audit the actual production callers, not just direct repository fixtures.

Derive lifetime event/receipt bounds from every producer, including challenge and
delivery attempts, reserved revocation and identity completion. The server ACK capacity is 602212, covering one ACK per supported lifetime
event. The consumer local directory capacity remains an independent operational
limit; operators retain full archives and select a fresh private directory when
needed. No server identity or audit quota is reset by archive rotation.

This document does not assert completed implementation, new proof discharge,
complete snapshot export/import or successful product release.

## Bound derivation and disclosure projections

Under the actual bounded production paths, per-domain lifetime event upper bounds
are 12048 organization commands, 30000 membership commands, 10164 configuration
changes including bootstrap and reserved cancellation, 450000 invitation events,
80000 identity-request events and 20000 administrative-grant events: 602212.
Invitation events include issuance, at most three acceptance mutations, at most
five invitation delivery claims and one terminal result, and five challenges each
with creation, five delivery claims and one terminal result. Identity requests
have one creation, five claims, one terminal result and one completion; their
10000 limit applies to the entire Environment, hence also each domain.
Uncertain delivery results add no event and terminal results cannot repeat.
Imported/historical inventories require separate validation of these bounds.

Every new ACK consumes at least one previously pending event; an exact replay
allocates none. Thus 602212 receipts cover even one-event batches, without relying
on compressibility or average event size. The same domain lock serializes capacity,
current authorization, event production and acknowledgment bookkeeping.

New event data is an object of at most 28 KiB compact UTF-8 JSON, nesting depth at
most 16, and integer numbers only. The integer restriction prevents PostgreSQL
numeric exponent expansion. JSONB rendering inserts bounded whitespace; the
existing 60 KiB transfer guard and page limit remain fail-closed. Writer validation
occurs before audit insertion, and any refusal rolls back the surrounding state
change. This does not authorize dropping an oversized historical event.

Role-policy events retain policy and per-role version identifiers rather than two
complete privilege configurations. Client-binding events retain binding/client
registration IDs, active state, before/after revisions and a configuration digest.
These explicit projections preserve version provenance without allowing a valid
maximum-size configuration to create an unreadable audit row. Complete current
configuration belongs to its authorized API and consistent snapshot contract.
