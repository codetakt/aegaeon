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
