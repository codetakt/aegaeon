# Organizations identity lifecycle

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This contract implements ORG-R05/R06/R10/R14, ORG-G05/G07/G09 and
ORG-P04/P05/P06/P07/P13. It does not discharge a composite proof obligation.

Every original Organizations approval captures the permanent user UUID, exact
subject, positive identity revision and original authentication time. Primary
checks require the same active identity revision and authentication strictly
after its reauthentication cutoff. Exchange, introspection, the own resource
server, retained delegated invitations and recipient acceptance use this check.
A new grant after recovery requires actual new authentication; exchanging a
parent or refreshing a token never advances authentication time.

Forward migration adds `organization_identity_revision` (initially 1) and
`organization_reauthentication_after` to users. New users begin with cutoff 0;
existing users receive the migration cutoff, requiring later authentication
before their first Organizations approval. Database
triggers monotonically advance the revision and cutoff on status or subject
changes and password credential creation, replacement, revocation or removal.
Changing password use timestamps does not advance them. Credential ownership
cannot be reassigned. Existing identities, subject ownership and memberships
remain intact; status restoration does not restore previous authority.

The cutoff is the primary database clock rounded down to epoch seconds. Since
OIDC authentication time uses seconds, authentication in the same second is
conservatively refused; authenticate again in a later second. Clock rollback
cannot lower the cutoff. A cutoff or revision update cannot decrease either
value. Revision saturation at signed 64-bit maximum is terminal for Organizations
authority; suspension and deletion still work. A higher revision or cutoff alone
can only revoke. No runtime can disable the triggers or replace their functions.
The physical catalog, compiled function definitions and migration hashes cover
these enforcement objects. Installer and privileged restore premises remain
separate from normal runtime checks.

The SQL trigger functions execute with the caller's permissions and fixed
`pg_catalog, pg_temp` search path. They have no public executable entry or new
security-definer authority. Trigger installation needs table TRIGGER and function
EXECUTE privileges as specified by the
[PostgreSQL 18 CREATE TRIGGER contract](https://www.postgresql.org/docs/18/sql-createtrigger.html).
The restricted-runtime integration test must exercise actual firing after
installation, including rollback attempts and counter saturation.

Original snapshots lacking the revision refuse decoding. Before deploying this
unreleased Organizations format, drain the affected browser approvals, token
records and invitation challenges; never populate missing authority fields with
current values. This is an Aegaeon profile requirement, not a new OIDC claim.
Identity recovery cannot activate a suspended identity or restore an old grant.
Restoring a historical database requires the separate nonrollback restore epoch
contract; identity counters alone do not establish restore safety.
