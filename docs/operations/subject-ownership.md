# Permanent OIDC subject ownership

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

Aegaeon permanently assigns each case-sensitive, ASCII OIDC subject to one
end-user UUID within an issuer namespace. A renamed user can return to a subject
that it previously owned. Another user cannot acquire that subject after rename,
soft deletion, physical deletion or restore. End-user UUIDs are permanent global
tombstones and cannot be recreated or moved between environments. Subject text
uses PostgreSQL `C` collation and retains the existing 1–255-byte format.

This changes database writes and the Rust server construction API. It does not
prove that an operator's imported historical records are complete or authentic.
Those are explicit deployment premises, supported by retained source records and
an authorized completeness attestation.

## Database identities and privileges

Use distinct existing login identities for migration, ordinary runtime and
history maintenance. An administrator reviews and runs
[`provision-subject-ownership.sql`](../../scripts/operations/provision-subject-ownership.sql)
with `psql -v runtime_role=… -v migration_role=… -v maintenance_role=…`.
The script defaults to rollback. Add `-v commit=true` only after reviewing its
inputs. It refuses incompatible existing roles/grants instead of revoking them.
Run it before migration to create the two restricted NOLOGIN groups and again
after migration to validate the final effective privilege boundary.

Direct INSERT/COPY/conflict insertion into the four authority tables also requires
the exact dedicated owner identity, enforced by SECURITY INVOKER triggers even if
an ordinary caller accidentally receives table DML permissions. Only the fixed
fresh-namespace, end-user and adoption definer entries supply that context.

The runtime login must not own the database/schema, protected relations or
functions, create objects in the protected schema, assume a privileged role,
set `session_replication_role`, mutate permanent tables, or call history helpers
and adoption functions. Inherited and `SET ROLE` paths are checked. Its ordinary
application DML/view permissions remain the administrator's responsibility.
The runtime also receives SELECT on the fixed Atlas revision relation for the
existing startup schema check; revision mutation remains forbidden.
Audit INSERT and SELECT remain supported, including management reads/export.
The audit parent and every attached descendant, including subpartitions and
partitions outside `aegaeon`, must deny reachable ownership, UPDATE, DELETE,
TRUNCATE, TRIGGER and column UPDATE to the runtime. Direct, inherited and
SET-reachable privileges are checked before startup and history adoption.
Apply the forward audit-authority migration after draining existing processes.
If preflight refuses existing grants, have the administrator review and remove
the forbidden rights from the identified runtime role paths before restarting
or adopting history. The migration does not revoke grants automatically.
Only this explicit runtime login receives the fixed, read-only namespace
validation entry. Do not grant that entry to PUBLIC or unrelated roles.

The maintenance login has EXECUTE-only access through
`aegaeon_subject_maintenance`; it must not have direct access to the source or
permanent tables or assume object ownership. The dedicated owner has the
SELECT/UPDATE permissions needed for source locks and fixed SECURITY DEFINER
functions; callers do not inherit that identity. Pre-migration inspection uses
an already authorized migration/DBA connection with SELECT and lock privileges.
It does not elevate an EXECUTE-only maintenance login.

## Stopped cutover

1. Stop and drain all issuer-serving processes, background workers, management
   writers and provisioning/import jobs. Exclude ordinary DDL and audit partition
   attach/detach throughout inventory and adoption. Retain a complete database
   backup, audit partitions, external journals and previous receipts privately.
2. Build the maintenance binary from reviewed source with the pinned toolchain:

   ```sh
   nix develop -c cargo build --locked -p aegaeon-server --bin aegaeon-subject-ownership
   ./target/debug/aegaeon-subject-ownership --help
   sha256sum ./target/debug/aegaeon-subject-ownership
   ```

   The artifact is `target/debug/aegaeon-subject-ownership` (under
   `CARGO_TARGET_DIR` instead when explicitly configured). Invoke this maintenance
   binary directly: pre-migration inventory intentionally operates on the old
   schema and must not use the guarded serving launcher.
   Released use requires a reviewed, signed source/build record. Retain the
   executable SHA256 and that record. Dirty builds are limited to isolated
   candidate validation or reproduction and require an exact retained input
   record; a Git commit label alone is not their build identity.

   Create the private JSON file passed as `--tool-source-record` with exactly
   these four fields (no extra fields):

   ```json
   {
     "tool_sha256": "<64 lowercase hexadecimal characters for the executable SHA256>",
     "source_commit": "<40 lowercase hexadecimal characters for the reviewed commit>",
     "source_tree": "<40 lowercase hexadecimal characters for the retained source tree>",
     "dirty_input_sha256": null
   }
   ```

   Replace every placeholder with the actual hash from the retained build
   record. Both nullable fields must be present: use JSON `null` for an absent
   `source_commit` or `dirty_input_sha256`, never omit the field. At least one
   must be non-null. For an isolated dirty candidate, set `dirty_input_sha256`
   to the exact input record's 64-character lowercase SHA256 and pass that file
   as `--dirty-input-record`; omit that option when its digest is null.
   The CLI checks the running executable and supplied dirty record hashes.
   Source review, signature verification and source/build authenticity remain
   the operator's responsibility.
3. Run `aegaeon-subject-ownership inventory --pre-migration` against the old
   database with `--environment-id`, `--deployment-id`, `--runtime-role`,
   `--tool-source-record` and a new `--output-dir`. Use `--dirty-input-record`
   when the build record names one. Connection configuration is the explicit
   `--database-url` or existing `AEGAEON_DATABASE_URL`.
4. Review all-environment current users, every status and the complete attached
   audit corpus. The private snapshot preserves exact source text and stable row
   locations. The distinct pre-migration format is never an adoption CAS input.
   Retain the snapshot and every repair disposition as external history sources.
   No known conflicting ownership can be waived by an attestation. Empty audit
   event types remain exact empty finding origins; they require the same evidenced
   resolution as other unrecognized history and must not be discarded.
5. Provision identities, then apply the strict Atlas migration. Invalid current
   subjects or current ownership conflicts abort installation. Diagnostics give
   counts and the first 100 ordered environment/user UUID locations without
   subject text; the pre-migration snapshot contains the complete input. Do not
   disable triggers or change migration checks to force installation.
6. Run final provisioning. Every environment that existed at installation is
   `legacy` and remains pending until reviewed history adoption. Environments
   created after installation receive a `fresh` receipt in the same transaction;
   this must not be used to recreate a deleted issuer or bypass legacy history.
7. With the maintenance login, run normal `inventory` for one target environment.
   Prepare the strict version-one manifest and explicit local `--source ID=PATH`
   mappings using the schemas in [`spec/subject-ownership`](../../spec/subject-ownership/).
   Account for all observed target and global owner facts, invalid disclosures,
   unknown/unscoped history and external records. Source references are labels;
   the tool never fetches URLs or opens a manifest-supplied path implicitly.
8. Run `adopt` with `--manifest`, `--inventory` and every source mapping. The
   default validates and rolls back. Review the retained attempt and its hashes.
   Commit with `--commit --expected-manifest-sha256 …
   --expected-inventory-sha256 …`. The transaction rechecks locked source and
   physical state, imports the preserved union, writes the audit event and
   creates the immutable receipt atomically. Repetition refuses mutation.
9. Verify the receipt and exact artifact identities, then start the server using
   the restricted runtime login. Startup validates actual environment/issuer,
   protected physical definitions and ACLs, and every compiled Atlas revision.
   Confirm readiness and perform the deployment's protocol checks before opening
   traffic. A pending namespace cannot publish subjects or perform protected
   identity/session operations.

Every attempt uses a new private directory. Preserve failed and rolled-back
attempts. Artifacts contain identity history and must not be attached to public
issues or logs. Hash and retain originals; share separately frozen redacted
copies when necessary. A transport error after commit is an uncertain outcome:
inspect the retained receipt and actual database before retrying.

## Failure and restore

Runtime namespace failure returns HTTP 503 without consuming protected one-time
state. Management ownership conflicts return HTTP 409 with fixed text and no
historical owner disclosure. Health, public discovery/keys, authenticated token
revocation, unrelated management and normal 404/405 behavior retain their existing
admission rules. Readiness and logout callbacks require the namespace capability.

Audit parent or partition RLS is rejected. A filtered audit view cannot establish
complete historical input. Physical catalog, role or revision changes invalidate
inventory/adoption comparison. PostgreSQL SECURITY DEFINER checks inspect the
installed physical contract and predecessor hashes; the normal Rust CLI and
runtime independently check every final compiled migration hash as well. An
administrator able to replace the database or installed code remains outside
this ordinary-writer guarantee and must use the stopped recovery process.

Back up and restore the four permanent authority tables together with the full
identity data, issuer/environment mapping, audit corpus, roles/ACLs, migration
revision history and immutable external receipts. Never restore only live users,
truncate ownership history, delete namespaces during cleanup, or replay a stale
backup into a serving issuer. Stop/drain, reconcile every assignment since the
backup from retained records, revalidate completeness and physical authority,
and only then restart. If history is incomplete, keep the issuer stopped; absence
of a current row is not evidence that its subject or UUID is unassigned.

## Rust construction and embedding

`AppState` identity/database fields are private. Struct literals, external pool
injection and mutation of identity services are no longer supported server
construction APIs. Use `AppState::from_environment().await?`, which creates its
own pool, validates the namespace and starts the same required supervised
monitors as the executable. It exposes no raw pool alias or unchecked capability.
A new database, issuer, configuration or identity-service generation requires a
new validated factory result. Client projection refreshes retain the namespace.

An embedder must observe `state.shutdown_requested()` and stop accepting/drain
its listener when it resolves. For example, clone the opaque state for that wait
and pass the other clone to `web::build_router`; attach the wait using Axum's
`with_graceful_shutdown`. A restart request refuses new protected admissions.
Work already holding a namespace capability may complete while the listener
drains; the capability does not hold a database transaction across Redis work.
Finish draining all such work before privileged schema, role, database or
history changes, then construct a new validated runtime. Keep the Tokio runtime alive
for the required monitors. The factory initializes the shared TLS provider but
does not configure tracing or parse the executable's arguments.

Standalone protocol/token helper APIs are not a replacement for the server
factory. Their caller remains responsible for supplying a validated, permanent
issuer/subject ownership authority and composing token, UserInfo, projection and
session operations with it. Constructing an individual helper does not confer
Aegaeon's server namespace capability or establish deployment assurance.

Inventory cursors fetch fixed batches of at most 256 rows while retaining one
locked transaction and the complete ordered corpus. This bounds rows per fetch,
not the byte size of an individual source row. Existing document capacity
refusals and private failed-attempt artifacts still apply.
