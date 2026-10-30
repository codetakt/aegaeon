# Permanent subject ownership integration

Last updated: 2026-10-29

Status: active plan

Owner: Engineering / Verification

Audience: implementers, reviewers, operators

## Integration target

Integrate the permanent ownership foundation from PR #167, revision
`7ffc2a61cdc588a7d2d7514356b032a3110bd6ad`, onto actual main
`4476e94d4058d4de811bc958c0e8c26a90d97732`. PR #163 is already merged.
PR #283 at `3f91a7e1a4732beb56fb4279cddab18c625d9d31` reconstructs the same
foundation against the unmerged attribute branch #217. It is an integration
reference, not a second ownership mechanism or additional proof discharge.
The attribute storage dependency is not required to deliver Organizations.
Its namespace fixture updates are reviewed against current protocol behavior.

Retain immutable issuer/subject reservations, global user UUID ownership,
explicit stopped historical adoption, the restricted runtime factory, runtime
drain admission, physical catalog checks and audit-history privilege checks.
Current-main JWT verification, upstream binding/cache policy, logout confirmation
and schema migrations take precedence over older versions of those components.
Moving runtime construction into the library must preserve those current paths.

## Identifier and lifetime boundaries

New generated local subjects use plain UUIDv4 strings. This is a separate
generation change and does not rename historical or explicitly supplied valid
subjects. UUID shape is not evidence of ownership. Stable `(issuer, subject)`
reservations and end-user UUID tombstones remain authoritative after rename,
deletion and restoration.

Native Organizations retains a separate internal UUID and exact external
selector per Environment/domain. Its membership owner reference must agree with
the permanent end-user owner relation. Existing candidate #167/#283 catalog
expectations cannot simply be declared compatible with the added organization
schema; source, migrations, installed definitions, ACLs and runtime validation
must correspond on the composed version.

## Migration and catalog contract

The unmerged ownership migration candidates are not current-main migrations.
Use new migration timestamps after the current-main inventory; retain all
already-main migration bytes. Bind the physical checker and independent compiled
checker to that exact inventory. A native Organizations follow-up must advance
the protected catalog expectations with its schema changes, without rewriting
historical ownership/adoption receipts or dropping permanent owner records.

Existing installations that ran an unpublished candidate require an explicit
stopped reconciliation; the new sequence is not an automatic alias for those
histories. Fresh and current-main upgrades, restricted roles, stale revisions,
tampered catalogs, audit permissions and history adoption need actual database
tests before this integration is accepted. Restore admission and Organizations
recovery epochs remain distinct obligations before activation.

## Review disposition and limits

PR #167's missed restart notification and audit partition authority findings are
valid and have corresponding fixes in the pinned candidate source. They require regression
on the integrated artifact. Its batch-fetch improvement is retained.
The in-flight publication comment is governed by the documented drain contract:
new admissions stop after restart, already admitted work may finish, and privileged
mutation waits for drain. This does not promise cancellation of all in-flight work.

The disposable-database administrator connection finding is valid: the fixture
must select the runtime's actual database via `test_admin_pool`. Direct runtime
SELECT of private adoption receipts is unnecessary and is removed from
provisioning, with a restricted-role regression that observes SQLSTATE `42501`
while ordinary namespace validation still succeeds. The two hard-coded password
findings refer to synthetic users created inside ignored, `cfg(test)` acceptance
fixtures. Their hashes are inserted into the owned disposable database and used
only by the local test router; neither is a production credential or default.
Retain those fixtures and document the scope rather than treating a scanner
comment as evidence of an exposed production secret.
Review-thread state is not itself acceptance or proof evidence.

| PR #167 comment | Disposition | Current correspondence |
| --- | --- | --- |
| 4167065449, missed restart notification | Valid; retain the corrected subscribe-before-check implementation. | `runtime_restart` regressions exercise notification before, during and after registration. |
| 4167065503, in-flight publication | Valid against the old runbook promise; use the explicit drain contract above. | New admissions refuse; an already borrowed capability may complete. Stopped maintenance still requires complete drain. |
| 4167065554, audit privilege omissions | Valid; retain the forward audit-authority migration. | Parent/recursive descendants, effective role reachability and column privileges are checked; a real unsafe grant is rejected by the factory fixture. |
| 4167065606, row-at-a-time history cursor | Valid; retain bounded batches. | Pre-migration collection fetches 256 rows per cursor batch without persistent statement metadata. |
| 4167608581 / 4167608613, fixture passwords | No production secret exposure in the inspected paths. | `login_consumption.rs` and `management_fixture.rs` create synthetic fixture users and exercise their real hash/login paths. |
| 4167620083, wrong administrator database | Valid; fixed. | Fault injection derives the runtime database name while retaining explicit setup credentials. |
| 4167620143, private receipt SELECT | Valid; fixed. | Provisioning removes the grant; the restricted-role regression rejects direct reads. |

Integration validation also found old test suppliers assuming runtime CREATEDB,
DDL and audit mutation rights. Only setup, cleanup and narrowly scoped fault
injection use the administrator connection. Product operations keep restricted
runtime connections. A supplier replacement must obtain a new namespace permit;
tests cannot manufacture one or bypass validation to restore an old expectation.
Actual connection failure and fresh-runtime recovery are distinct from rejecting
an unvalidated replacement. The preexisting test runner executes from
`crates/server`; helper script lookup now uses that runtime location rather than
Nix's deleted compile-time `/build/source` path.

The schema snapshot is regenerated from the installed PostgreSQL 18 migration
sequence, with the fixed ownership/privilege contract retained. A failed merged
snapshot with duplicate historical DDL is retained in the private implementation
record. All 14 already-main migration SQL files remain byte-identical. Neither
that regeneration nor passing focused tests constitutes deployment acceptance.

The public-client key migration retains its predecessor-row preservation,
atomic-refusal, constraint and no-op transformation controls. That older schema
now explicitly refuses serving without the subject namespace. Its authenticated
read/update/signature/registration-token controls execute separately on a fully
migrated restricted database. They do not establish historical adoption from that
predecessor through the complete ownership upgrade; that remains an integration
and operational evidence obligation.

This work maps to ORG-R02 / ORG-G02 / ORG-P02 and the associated same-system
catalog and deployment obligations. Integration, passing tests, formal proof
discharge and release acceptance are separate. New formal discharges remain zero.
