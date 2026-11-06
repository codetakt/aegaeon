# Durable audit outbox consumption

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: Implementers, operators and security reviewers

## Scope and authority

This contract concretizes ORG-R16/R20/R21, ORG-G03/G11/G13 and
ORG-P03/P06/P10/P12/P14. Runtime and consumer implementations accompany it;
validation records and composite proof discharge remain separate.
Every fetch, acknowledgment and replay requires current domain Export. Human
operators authenticate through the existing management session. An unattended
consumer authenticates with a service API key carrying the explicit
`organizationAuditExport` capability AND an Export grant for that service
administrator in the target domain. Neither `read`, `auditRead`,
`teamAdministration` nor Team ownership substitutes for either machine gate.
The immutable audit history remains readable after acknowledgment.

Under the existing Team/Environment/domain management base, GET/HEAD
`audit-events/pending` returns a bounded batch of undelivered outbox events. POST
`audit-events/acknowledgments` confirms the exact batch after durable recipient
storage. All acknowledgments require Idempotency-Key and exact If-Match. Human session
mutations also require Origin/CSRF. Service requests use Bearer authentication,
reject Cookie, and receive no browser session or CSRF exemption for cookie-based
requests. Machine authority is limited to pending-batch fetch and acknowledgment;
history browsing, snapshots, configuration, membership and support operations
retain their existing human or protocol authority requirements.

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

The distribution includes `aegaeon-organization-audit-consumer`, built from
`scripts/organization_audit_consumer.py` with the pinned Python runtime. Its
outer 35-second process deadline and five-second termination grace also bound
startup and blocked I/O; the consumer retains its inner 30-second deadline.
It connects only through the authorized HTTPS management API and receives no
direct database credential or runtime authority. The consumer saves a fresh private batch directory, exact payload,
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

The pinned OpenSSL default trust loader honors Nix's `NIX_SSL_CERT_FILE` when
present. When selecting a private CA bundle, set both `NIX_SSL_CERT_FILE` and
`SSL_CERT_FILE` to that same trusted file. An inherited Nix build setting such as
`/no-cert-file.crt` intentionally supplies no default trust. Certificate and
hostname verification remain mandatory; the consumer has no insecure TLS option.

```sh
aegaeon-organization-audit-consumer fetch --state /private/audit \
  --session-file /private/session.json \
  --base https://issuer.example/api/v1/teams/TEAM_UUID/environments/ENV_UUID/organization-domains/DOMAIN_UUID
aegaeon-organization-audit-consumer ack --state /private/audit \
  --session-file /private/session.json --batch BATCH_UUID
```

Fetch prints the local batch UUID. ACK checks the retained payload, event files,
manifest, source and ETag again, fsyncs files/directories, and sends the saved
request with its original key. A partial manifest cannot authorize ACK. A partial
temporary receipt can be replaced on retry; completed event, batch, manifest and
receipt files cannot be overwritten. Local retries still require a current
credential and Export grant. Separate operators have separate receipt keys;
use the original principal when recovering an uncertain ACK.

Local admission retains at most 10000 batch directories, including interrupted
ones, and at most 100 event files per admitted batch. No automatic pruning or
quota reset is provided. File payload bounds do not establish physical disk-space
bounds, which also depend on filesystem allocation and metadata.

## Unattended operation

Create a dedicated API key through `POST /api/v1/teams/{teamId}/apiKeys` with
`capabilities: ["organizationAuditExport"]` and an explicit bounded expiration.
The one-time response contains the secret `apiKeyValue` and the public
`apiKey.serviceAdministratorId`. A current human Configure operator then uses
`POST .../organization-domains/{domain}/operators` to grant that principal only
`["export"]`. This uses the existing audited grant transaction, revision and
per-domain operator quota. Service principals cannot be granted Configure,
Provision, Reconcile or Support; they cannot grant themselves Export.

Keep `{"apiKey":"<one-time issued value>"}` in an owner-only 0600 file supplied by
the operator's secret store. The consumer accepts `--api-key-file` instead of
`--session-file`, never both. It sends only the Bearer credential, with no Cookie,
Origin or CSRF token. Credential bytes are not saved in retained audit batches.

```sh
aegaeon-organization-audit-consumer fetch --state /private/audit \
  --api-key-file /private/audit-key.json \
  --base https://issuer.example/api/v1/teams/TEAM_UUID/environments/ENV_UUID/organization-domains/DOMAIN_UUID
aegaeon-organization-audit-consumer ack --state /private/audit \
  --api-key-file /private/audit-key.json --batch BATCH_UUID
```

An external scheduler invokes these finite operations and retains failed batches;
the product does not hide an unbounded retry loop. Both fetch and ACK validate the
current service account, active Team/Environment/domain and Export grant. Before
commit, they lock the current API key and its explicit capability, recheck the
secret binding, status, team, service identity and expiry using the DB clock.
Expiry is evaluated after acquiring the credential lock, including any wait for
a concurrent writer. Revocation is serialized against that lock. Existing domain/grant locks retain
current Export through commit, including a stored receipt replay. A failed final
check rolls back delivery bookkeeping and releases no event response.

Receipts identify the service principal and `management-api-key:<key UUID>`;
secrets are excluded. Key rotation creates a new service principal and requires
its own domain grant. Resolve uncertain ACKs with the original authorized
principal before retiring its credential; a new key does not inherit old receipt
authority. Revoking the key, disabling the service account, removing Team
membership, revoking domain Export or disabling the domain stops subsequent
machine access. These facts are part of the selected database state after an
operator-chosen restore; the external audit copy does not reapply revocations.

Local custody still requires an independently durable destination for PITR or
loss of the primary database host. The consumer's fsync and acknowledgment
contract is unchanged; successful authentication alone proves no external
storage durability or provider acceptance.

## Retention and remaining scope

Event, receipt and ownership retention is permanent in this profile. Neither
acknowledgment nor receiver deletion removes server history or releases identity
quotas. Derive the total finite domain bounds from every authority, membership,
invitation, challenge, delivery and receipt limit before stating storage bounds.
Normal-operation capacity and reserved cancellation must both be demonstrated.

Pending delivery batches are not a complete, consistent migration snapshot.
Full authorized export/import, single-writer cutover and an independent
nonrollback authority epoch remain separate required implementations.

## Distribution regression

The required packaged protocol journey runs this consumer against the actual
server and restricted stores after registration, delegated invitation acceptance
and membership changes. It explicitly grants Export, traverses immutable history,
retains exact event bytes twice, refuses corrupt local custody before ACK and
rejects a same-ID/different-digest collision. A frontend discards one successful
ACK response after the server commits; a new consumer process recovers using
the retained batch and original key. Receipt replay leaves history unchanged.
Revoking Export refuses a later replay even when a local receipt already exists.
The event output is checked for the fixture's passwords, capabilities, client
secrets and recipient addresses.

Separate process-kill, fsync-failure, TLS, byte-bound and deadline tests retain
their narrower consumer scope. The combined journey does not qualify disk
hardware durability, a production operator's custody, every transition's trace
correspondence or the full audit proof family.
