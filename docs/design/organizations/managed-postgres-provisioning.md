# PostgreSQL administrator provisioning boundary

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: operators, implementers, security reviewers

## Confirmed failure and scope

The report used PostgreSQL 18.6 locally, a `NOSUPERUSER CREATEDB CREATEROLE`
login and source `48a42d2bf`. It did not use RDS. The original claim that RDS
could not install this release was an inference and was withdrawn.

With default `createrole_self_grant`, the old test fixture first failed at
`CREATE DATABASE ... OWNER`: the creator could administer the generated migration
role but could not SET ROLE to it. Isolating the real ownership provisioning SQL
then reproduced `subject owner has an unexpected member`. With `set,inherit`,
fixture database creation succeeded and provisioning failed at that same check.

A diagnostic copy allowing `current_user` through both member filters proceeded
to the final maintenance preflight and failed. Removing every optional self-grant
still reproduced `maintenance actor can bypass protected authority`: the recursive
member enumeration treated the database administrator's ADMIN-only membership as
an ordinary execute-only maintenance consumer.

[PostgreSQL CREATE ROLE](https://www.postgresql.org/docs/18/sql-createrole.html)
documents the creator's automatic ADMIN grant by the bootstrap superuser, with
INHERIT and SET disabled. The optional
[createrole_self_grant](https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-CREATEROLE-SELF-GRANT)
adds separate execution rights. AWS documents that its
[RDS master user is NOSUPERUSER](README.md#provider-reference).
These documents motivate compatibility work; they do not establish actual RDS
catalog behavior or successful provisioning.

## Adopted privilege boundary

A database administrator already able to administer both protected groups can
change their members and ultimately assume object ownership. It is outside the
execute-only maintenance threat boundary. Provisioning and preflight recognize
this existing capability only when the same principal has ADMIN-only grants on
**both** `aegaeon_subject_owner` and `aegaeon_subject_maintenance`, with INHERIT/SET
false, from the same superuser grantor. No role name, `current_user`, CREATEROLE
flag alone or non-superuser delegation grants this exception. These catalog rows
identify capability; they do not authenticate the historical cause of a grant.

Provisioning allows that administrator's membership and explicitly grants the
acting administrator owner INHERIT/SET for installation of object privileges.
This is an explicit use of existing ADMIN power and is independent of the global
self-grant setting. It does not assign elevated rights to runtime or maintenance
logins. The disposable fixture separately grants its generated migration role to
its own administrator so database creation and schema grants work with defaults.

Preflight excludes the administrator branch from execute-only consumer traversal.
All ordinary maintenance members remain checked. Runtime membership in either
protected group and maintenance membership in the owner group are refused even
when only ADMIN is enabled. Unknown extra members, incompatible group parents,
unsafe role flags, protected object grants and catalog drift remain refusals.
Existing unrelated grants are not silently revoked.

The repair is part of the sole new Organizations migration; the 24 pre-PR
migrations are unchanged. Exact function-body hashes, Atlas revision binding and
`db/schema.sql` are updated together. No trial-state upgrade path is promised.

## Ordinary application grants

Use a dedicated `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`
login for runtime. Create the database with the migration role as owner. On
PostgreSQL 16 and later, a non-superuser database creator also needs explicit
SET membership in that owner role; automatic ADMIN membership alone is not SET.
Run the ownership provisioning script before migration to create the protected
roles, then apply the pre-PR-to-PR migrations using the migration login. Run
ownership provisioning again after migration before the following grants.

With `PGHOST`, `PGDATABASE` and the installation administrator's authentication
configured securely, apply the reviewed ordinary application allowlist and then
the protected Organizations grants:

```sh
psql -X -v ON_ERROR_STOP=1 -v runtime_role=aegaeon_runtime \
  -f scripts/operations/provision-runtime.sql
psql -X -v ON_ERROR_STOP=1 -v runtime_role=aegaeon_runtime -v commit=true \
  -f scripts/operations/provision-runtime.sql
psql -X -v ON_ERROR_STOP=1 -v runtime_role=aegaeon_runtime -v commit=true \
  -f scripts/operations/provision-organizations.sql
```

The first invocation validates the ordinary grants and rolls them back. Both
scripts default to rollback; `commit=true` explicitly persists the transaction.
Reapplying these grants is idempotent. They check the subject-ownership privilege
boundary before and after applying permissions and refuse incompatible existing
authority rather than silently revoking it.

For a distinct management writer, set `runtime_role` to that writer and
`authority_runtime_role` to the existing primary runtime login. The latter
defaults to `runtime_role` for the ordinary one-credential procedure. Global
catalog preflight must retain the actual snapshot-entry grantee; it cannot be
renamed to the management target. The target independently passes
`subject_history_check_runtime_role` before and after grants. This adds no
snapshot/history function authority to the management writer. The additional
LTI writer and lifecycle-read grants are specified in the
[LTI operator procedure](../../operations/lti-platform.md#release-local-attributes).

The ordinary script explicitly lists the current application tables, grants
append/read access to audit events and read access to attribute-source metadata,
and grants the one view-column permission needed for a locking read. It does not
grant ownership, schema CREATE, TRUNCATE, grant options or blanket future-table
permissions. Protected ownership, Organizations column privileges and lifecycle
activation remain in their dedicated procedures. An application schema change
must review this allowlist. Future audit partitions accessed through the parent
do not require direct child-table privileges for runtime queries.

The operational fixture now uses this exact ordinary runtime procedure. Its
separate management test actor retains test-only grants; that actor is not a
production installation requirement. Local non-superuser preparation and the
packaged startup/recovery checks therefore exercise the published runtime grants.

## Verification and remaining qualification

The required catalog upgrade check now runs the actual `prepare_runtime` and
provisioning scripts under a non-superuser administrator on separate owned
PostgreSQL clusters with default and `set,inherit` settings. Both must complete
all migrations and final preflight. Eight negative privilege conditions per
setting must produce their expected refusal, including operational ADMIN-only
membership, incomplete administrator authority, non-superuser delegated grants,
group inheritance and an unrelated owner-group member. Supplier cleanup is owned.
The populated pre-PR upgrade, rollback/retry, fresh/schema/dump correspondence and
existing corruption checks also remain required.

Actual RDS provisioning, failover, PITR, connection limits and provider-specific
roles remain unqualified. Do not replace that qualification with a local
superuser setup or infer compatibility merely from the local successful path.
Independent acceptance and Task 1b/Task 3 proof boundaries remain unchanged.
