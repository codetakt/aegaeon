# Client DPoP requirement upgrade

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

The `clients.dpop_bound_access_tokens` boolean is a client-owned requirement under
RFC 9449 §5.2. New registrations default to false. True requires a valid DPoP
proof on every token grant; it conflicts with effective mTLS policy. False does
not remove an environment/profile requirement or a binding on an already issued
refresh, access or exchange token.

The predecessor did not retain this metadata. Migration
`20261002120000_client_dpop_minimum.sql` deliberately leaves every existing client
row unresolved (`NULL`), including deleted clients, noncurrent configurations,
and deleted environments. It does not reconstruct lost intent.
An operator must make an explicit current configuration decision for every row.
A matching server refuses startup until all retained rows are resolved. A
configuration switch refuses unresolved rows anywhere in its environment.

## Offline cutover

1. Preserve normal private database recovery material and the operator's intended
   choices. Stop all issuers, old readers and writers, including maintenance jobs.
2. Inventory retained clients on the predecessor using stable UUIDs, configuration
   membership and status. Do not infer choices from profiles or missing metadata.
3. Apply the source-managed Atlas migration with matching deployment tooling.
4. Run `scripts/operations/client-dpop-minimum-inventory.sql`. Preserve its version
   and encoding receipt privately and obtain a reviewed choice for every returned row.
5. Review and execute the one-row repair below. Keep all writers stopped between
   operations. Repeat inventory after each accepted operation as needed.
6. Require zero unresolved rows across the entire database, then start only matching
   readers/writers. Check normal schema/runtime readiness and targeted token requests.

No mixed-version or rolling upgrade is supported: an old binary can ignore a true
minimum. Once new choices are accepted, reverting only the binary or dropping the
column discards authority. Keep issuance stopped until compatible code/schema and
preserved choices have been restored. No automatic backfill or runtime skip exists.

## Inventory and repair identity

Both scripts use UTC and the complete current row, including timestamps and NULL:

```sql
pg_catalog.encode(
  pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.to_jsonb(c)::text, 'UTF8')),
  'hex'
)
```

This works with pgcrypto preinstalled in another schema. It does not relocate the
extension. Inventory and repair must use the same database, schema and PostgreSQL
version. Preserve `server_version`, `server_encoding`, `client_encoding`, executed
script SHA256 and the reviewed input in the private maintenance receipt.
SQL_ASCII is not a UTF8 guarantee. Serialization or conversion failure refuses;
this digest is not a cross-database canonical identity. The inventory never emits
the complete row JSON, secrets or credentials.

## Review one explicit choice

Use one administrator psql session, with `ON_ERROR_STOP` enabled. Supply the values
through psql quoted variables or bound parameters, never raw SQL substitution.
The nonsecret operation reference identifies a private change record; use 1–256
printable nonspace ASCII bytes and no credentials or personal data.

```sql
\set ON_ERROR_STOP on
-- Set environment_id, client_id, expected_row_sha256, choice and operator_reference
-- to the reviewed values in this private session before executing the following.
CREATE TEMP TABLE client_dpop_minimum_repair_input (
  schema_version integer,
  environment_id uuid,
  client_id uuid,
  expected_row_sha256 text,
  dpop_bound_access_tokens text,
  operator_reference text
);
INSERT INTO pg_temp.client_dpop_minimum_repair_input VALUES (
  1, :'environment_id'::uuid, :'client_id'::uuid, :'expected_row_sha256',
  :'choice', :'operator_reference'
);
\i scripts/operations/client-dpop-minimum-repair.sql
```

The script requires exactly one row and all fields. Choice must be the exact
lowercase text `true` or `false`; PostgreSQL abbreviations, numbers, whitespace and
uppercase forms are refused. The digest must be 64 lowercase hexadecimal characters.
Environment and client locks precede the fresh whole-row comparison. Wrong scope,
missing or stale rows, and already-resolved choices refuse. Do not substitute a
fresh digest without reviewing the intervening change.

The distributed script ends in `ROLLBACK`, so review leaves both the client and
audit unchanged. For an approved commit, preserve a reviewed copy whose only
change is the final `ROLLBACK;` to `COMMIT;`, record its digest, and run it with the
same one-row input in the same administrator session. There is no implicit commit
flag. Reusing a committed input refuses; inventory identifies the remaining rows.

## Atomic maintenance audit and limits

Repair changes only the selected boolean and appends
`maintenance.clientDpopMinimum.resolved.v1` in the same transaction. Audit failure
rolls back resolution. The record contains actual current/session database roles,
operation time, team/tenant/environment/client UUIDs, explicit boolean, expected
digest and operation reference. Its random `maintenance:` request ID is unrelated
to HTTP. It does not fabricate a registration acceptance time or HTTP identity.
Notifications and ordinary database triggers stay enabled; unrelated fields,
credentials and timestamps are preserved.

The existing audit UPDATE/DELETE restrictions apply to ordinary application roles.
They do not provide tamper resistance against the privileged administrator running
repair. Environment→client locks alone do not freeze tenant→team reassignment;
the stopped-all-writers premise remains required. This procedure is a configuration
operation, not proof of the predecessor's lost registration metadata, immediate
revocation of earlier tokens, or cancellation of already captured requests.
