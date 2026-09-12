# Recover configuration memberships after an incomplete activation

Last updated: 2026-09-12

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

The activation fix prevents future membership loss. It does not repair live
objects stranded on an older archived version by a previous activation. Runtime
readers select the current version's clients, profiles and connections; changing
the document again cannot recover those objects safely.

Use this procedure only when a pre-incident inventory, backup and activation audit
identify the exact objects that should have remained available. `ACTIVE` on an
archived version is not sufficient evidence. If the intended membership cannot
be established, keep the affected clients unavailable until the inventory is
resolved. Never select every historical row.

## Preconditions and approval

1. Deploy the activation fix. Stop traffic and every runtime, management, DCR and
   background writer for the target environment, including old binaries. Keep
   them stopped through rehearsal, approval and committed comparison.
2. Record the issuer, environment UUID, archived source UUID, expected active
   version UUID and exact client/profile/connection UUID arrays. Include referenced
   profiles unless already current. Use a separate operation per archived version.
3. Record the approved change request, reason, script version/SHA-256 and historical
   membership evidence. Obtain a protected backup and test restoration into a
   disposable database. Do not include backup or database credentials in transcripts.
4. Use an auditable database operator authorized to lock/read these rows, update
   the three membership tables and insert audit events. This is a database repair,
   not a management API action. The audit records the actual `session_user` as
   `DATABASE_OPERATOR`; it does not impersonate an administrator.

PostgreSQL 11 or newer is required by runtime fingerprints using
`pg_catalog.sha256(bytea)`. The repository integration lane uses PostgreSQL 18; the feature floor does not
mean every intervening version has been tested. Rehearse with the deployment's
pinned version.
Neither the activation fix nor this script requires a schema migration.

## Inspect and select

In a protected `psql -X` session, set `environment_id` to the approved UUID:

```sql
SELECT e.id, e.issuer_url, e.active_configuration_version_id,
       v.id AS version_id, v.version_number, v.status, v.configuration_hash
FROM aegaeon.environments e
JOIN aegaeon.configuration_versions v ON v.environment_id = e.id
WHERE e.id = :'environment_id'::uuid ORDER BY v.version_number;

SELECT 'clients' AS kind, id, configuration_version_id, status::text
FROM aegaeon.clients WHERE environment_id = :'environment_id'::uuid
UNION ALL
SELECT 'oauth_profiles', id, configuration_version_id, status::text
FROM aegaeon.oauth_profiles WHERE environment_id = :'environment_id'::uuid
UNION ALL
SELECT 'connections', id, configuration_version_id, status::text
FROM aegaeon.connections WHERE environment_id = :'environment_id'::uuid;
```

Compare with the approved prior membership, not just the current query. Preserve
the approved target configuration hash, member manifest and transcript. Never
print whole credential rows.

## Rehearse and apply

`scripts/operations/recover_configuration_membership.sql` accepts UUID arrays in
PostgreSQL syntax (`{uuid-1,uuid-2}`), with `{}` for an empty category. At least one
member is required. Duplicate/missing IDs, another environment, a changed active
pointer, a non-archived source and deleted/retired rows are rejected. Disabled
connections and expired but ACTIVE profiles preserve their state and expiry.

```bash
# Supply DATABASE_URL through the deployment's protected connection mechanism.
# Replace these example UUIDs with the reviewed manifest.
psql -X "$DATABASE_URL" \
  --set=environment_id=00000000-0000-0000-0000-000000000001 \
  --set=from_version=00000000-0000-0000-0000-000000000002 \
  --set=to_version=00000000-0000-0000-0000-000000000003 \
  --set=client_ids='{00000000-0000-0000-0000-000000000004}' \
  --set=profile_ids='{}' --set=connection_ids='{}' \
  --set=request_id=CHANGE-1234 \
  --set=reason='Recover the approved membership for CHANGE-1234' \
  --file=scripts/operations/recover_configuration_membership.sql
```

The default performs the entire transaction, including audit insertion, then
**ROLLBACK**. Rehearse first in the restored disposable database, then in the
quiesced target. Confirm selected counts, explicit ROLLBACK and unchanged database
state. Keep both transcripts. After operator approval, repeat the identical
manifest with `--set=apply=true`. Use only `true` or `false` for that flag and a
fresh `psql` connection for each attempt.

The script locks the environment, versions and target-environment rows, checks
the expected pointer, and updates only `configuration_version_id` on selected
members. Full before/after row comparisons inside the transaction reject any
other field or row-count change, including unselected rows, keys and secrets.
Credential provenance and lifecycle are preserved. The audit commits in the
same transaction. SQL/audit errors and lock/statement timeouts abort the run.

If COMMIT acknowledgement is lost, the outcome is unknown. Do not retry blindly.
Check selected memberships, pointer/hash and the exact audit request ID first:

```sql
SELECT event_type, outcome, actor_type, actor_id,
       from_configuration_version_id, to_configuration_version_id
FROM aegaeon.audit_events
WHERE environment_id = :'environment_id'::uuid
  AND request_id = :'request_id'
  AND event_type = 'CONFIGURATION_MEMBERSHIP_RECOVERED';
```

A repeated committed operation fails its source-membership check. An audit row
alone is insufficient; resolve any disagreement while writers remain stopped.

## Resume and verify

Start only the fixed binary and reload runtime state through the normal startup
procedure. Verify discovery/JWKS, fresh login/client authentication with a
recovered client, and rejection with an incorrect secret. Verify revoked
credentials and expired profiles still reject, disabled connections stay disabled,
and a second environment's configuration/membership inventory is unchanged.
Rehearse a later ordinary activation in the restored fixture to confirm recovered
rows are carried forward. Resume traffic only after these checks.

Recovery does not restore tokens, change policy or reset expiry. If a committed
repair was wrong, keep its audit and prepare an explicit forward repair under
maintenance. Do not reverse the active pointer, collect all archived rows, or
restore an old backup over a running system: that could undo later revocations.
