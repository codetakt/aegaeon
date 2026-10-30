# Durable audit outbox consumption

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: Implementers, operators and security reviewers

## Scope and authority

This contract concretizes ORG-R16/R20/R21, ORG-G03/G11/G13 and
ORG-P03/P06/P10/P12/P14. Runtime and consumer implementations accompany it;
validation records and composite proof discharge remain separate.
An authenticated current human domain operator must hold explicit Export on each
fetch, acknowledgment and replay. Other capabilities and Team ownership do not
substitute. The immutable audit history remains readable after acknowledgment.

Under the existing Team/Environment/domain management base, GET/HEAD
`audit-events/pending` returns a bounded batch of undelivered outbox events. POST
`audit-events/acknowledgments` confirms the exact batch after durable recipient
storage. Mutations require the existing interactive session, Origin/CSRF,
Idempotency-Key and exact If-Match. No service credential or arbitrary profile
claim substitutes for the management boundary.

## Batch identity and acknowledgment

The pending response has `version: 1`, `environmentId`, `domainId`, and ordered
`deliveries`, each containing `event` and `sha256`. The event digest is over the
exact UTF-8 bytes of the event JSON object in the response, including its number
lexemes and member order. Consumers must preserve those bytes; parse/reserialize
in another JSON runtime is not equivalent. The strong ETag is
`"audit-batch.<lowercase SHA-256>"`. Its hash input is compact UTF-8 JSON with
sorted object keys:

```json
{"events":[{"id":"event UUID","sha256":"event digest"}],"scope":{"domain_id":"domain UUID","environment_id":"Environment UUID"},"version":1}
```

Only ASCII UUIDs, lowercase hex digests and the integer version appear in this
hash input. This project-specific representation is not a general JSON
canonicalization claim. The tag is an integrity/precondition value, not authority.
No arbitrary supplied event payload is accepted by the acknowledgment endpoint.

A batch is at most 100 events and 64 KiB, with the existing finite admission,
10-second input and 30-second operation deadlines. Acknowledgment validates every
ID, scope and digest before any effect. Under the domain lock, current events and
outbox delivery state determine the exact batch precondition. Unknown IDs,
foreign scopes, changed payload or invalid tags cannot produce partial changes.
The POST body contains the ordered `events` ID/digest pairs and a nonempty
`reason` of at most 1024 UTF-8 bytes without controls. The same authorized
idempotency key and semantic batch returns its stored result;
a changed request conflicts. Validate current authority before receipt replay.
A distinct key attempting an already acknowledged batch receives a stale-state
refusal. A lost response is recovered using the original key and batch.

Delivery bookkeeping updates outbox status and appends a protected immutable
receipt atomically. The receipt records actor, request, exact batch and outcome;
it is the audit of the acknowledgment. The original authority events and their
outbox identities remain unchanged. Acknowledgment creates no new authority
mutation and no recursively deliverable acknowledgment event. All authority
mutations retain their state/event/outbox/receipt atomicity contract.

Acknowledgment receipts have a distinct finite per-domain capacity of 602212, independent
of authority and reserved-revocation receipts. At capacity, fetch and history
remain available and acknowledgment refuses explicitly; no history or quota is
silently reset. This bound derives from the supported lifetime event producers and permits one
ACK per event. Its caller/storage premises and full-capacity behavior require
validation; see [transition provenance](audit-transitions.md).

## Consumer custody and uncertainty

The consumer in `scripts/organization_audit_consumer.py` saves a fresh private batch directory, exact payload,
counts/digests and source identity, then fsyncs files and directory before POST.
An interrupted write never acknowledges. Failed or uncertain POST retains the
batch and idempotency key for bounded retry. A repeated fetch can repeat events;
receiver deduplication uses permanent event UUIDs and rejects same-ID/different-
digest content. An acknowledgment from an arbitrary external consumer is not
proof that consumer stored anything; durable custody is a separate supplier
premise, exercised with actual crash/restart and lost-response tests.

The consumer runs one operation with a 30-second absolute deadline. It requires
verified HTTPS, rejects redirects, accepts at most 64 KiB and 100 events, and
performs no automatic network retries. The state directory must already exist,
be owned by the invoking Unix user, and have mode 0700. The session file must be
a private regular file, mode 0600, with exactly `cookie`, `csrfToken` and `origin`;
the origin is the configured HTTPS management origin. Session material is never
saved in the batch. Keep this directory on storage whose fsync contract is
appropriate for the required durability; the client cannot prove disk hardware
or remote filesystem durability.

```sh
python3 scripts/organization_audit_consumer.py fetch --state /private/audit \
  --session-file /private/session.json \
  --base https://issuer.example/api/v1/teams/TEAM_UUID/environments/ENV_UUID/organization-domains/DOMAIN_UUID
python3 scripts/organization_audit_consumer.py ack --state /private/audit \
  --session-file /private/session.json --batch BATCH_UUID
```

Fetch prints the local batch UUID. ACK checks the retained payload, event files,
manifest, source and ETag again, fsyncs files/directories, and sends the saved
request with its original key. A partial manifest cannot authorize ACK. A partial
temporary receipt can be replaced on retry; completed event, batch, manifest and
receipt files cannot be overwritten. Local retries still require a current
server session and Export grant. Separate operators have separate receipt keys;
use the original principal when recovering an uncertain ACK.

Local admission retains at most 10000 batch directories, including interrupted
ones, and at most 100 event files per admitted batch. No automatic pruning or
quota reset is provided. File payload bounds do not establish physical disk-space
bounds, which also depend on filesystem allocation and metadata.

## Retention and remaining scope

Event, receipt and ownership retention is permanent in this profile. Neither
acknowledgment nor receiver deletion removes server history or releases identity
quotas. Derive the total finite domain bounds from every authority, membership,
invitation, challenge, delivery and receipt limit before stating storage bounds.
Normal-operation capacity and reserved cancellation must both be demonstrated.

Pending delivery batches are not a complete, consistent migration snapshot.
Full authorized export/import, single-writer cutover and an independent
nonrollback authority epoch remain separate required implementations.
