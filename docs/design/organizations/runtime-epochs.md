# Organizations runtime authority epochs

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers and security reviewers

## Contract

This refines ORG-R17/R18/R19/R21 and ORG-G10/G11, contributing to
ORG-P02/P06/P08/P10/P11/P12/P13/P14/P15. It follows the independent witness and
owned-work contract in [import activation](import-activation.md). It does not
qualify an independent supplier or enable production activation.

A protected epoch binding contains version 1, Environment UUID, immutable
deployment UUID, authority epoch UUID and the selected primary/token-store UUIDs.
All five identifiers must be nonnil and match the actual acquired witness
admission exactly. These are structured fields, not prefixes embedded in object
IDs. Public organization UUIDs, exact scoped external IDs, OIDC subjects and
standard token fields keep their existing representations.

A serialized binding is data, never an admission credential. A current witness
acquisition constructs the live comparison value after the fixed SQL supplier
checks its active selection. Deserialized metadata must match that value; merely
being well formed or matching a locally cached configuration is insufficient.
Missing fields, unknown versions, nil IDs and unknown fields refuse. No decoder
fills a missing epoch from current state. A retained binding can be compared
only inside an open owned-work boundary, which remains pending through every
primary/token-store operation and its confirmed cleanup.

## Protected record integration

The original consent snapshot and its immutable root authority must capture the
binding before display and recheck it at approval/code issuance. Authorization
code redemption, refresh lineage and selected-token metadata retain the exact
same binding; exchanging, refreshing or deserializing a record never upgrades it
to a new epoch. Original consent and selected authority use an explicit new
internal record version when that integration is introduced. Earlier records
remain historical and cannot grant Organizations authority without a fresh
original authorization.

Invitations, recipient challenges, enrollment/recovery requests and temporary
administrative grants require the corresponding protected binding at creation
and every use. Their migration preserves historical IDs and status separately
from capability usability. An imported or restored record never inherits the
selected epoch merely because its object UUID is unchanged. Audit and export
must retain the historical binding when their versioned format is extended.
The parser must distinguish a historical format from a current activation input.

These field integrations are subsequent implementation work. The typed binding
and witness coordinator alone do not establish their caller coverage. No new
JWT or introspection profile field is introduced by this component; any later
public extension requires its own versioned contract and compliance tests.

## Runtime admission and recovery

Organizations admission requires explicit configuration, a qualified independent
supplier, fresh current selection and verified selected-store identity. These
checks precede authority-bearing store work. The witness runtime login cannot
initialize, fence, prepare or activate authority. Maintenance credentials never
enter ordinary runtime state. Failure refuses with the existing unavailable or
inactive result; no positive decision cache or administrator bypass is allowed.

Primary cleanup is only one owner. Redis command/driver threads, proof workers,
root guards, session reads and detached HTTP workers must retain the same work
admission. A command timeout or transport close cannot prove that Redis finished
its mutation. Uncertain command completion must keep the durable slot pending
until qualified reconciliation. Connection preparation that cannot yet have
performed authority work is a distinct case and must retain its actual owners.

Primary connection cleanup has a 30-second absolute deadline covering protocol
draining, timeout restoration and pool return. Server statement deadlines cannot
bound a missing network response or a pool hook. Expiry closes local admission;
it never supplies completion evidence or clears a durable witness slot. Any
detached supplier work remains part of explicit reconciliation. This bounded
wait is independent of the request response deadline and the coordinator's
completion wait.

`Work::blocking` installs the admission on its owned synchronous worker thread.
Redis facades created there capture that admission; both the facade and its
driver retain it through runtime/resolver shutdown. A facade from another work
boundary or one opened outside the boundary cannot be used inside it. The scope
is thread-local, never process-global, and ends even on panic. Nested scopes and
untracked child threads are not supported; callers must keep all token-store
work in this boundary or explicitly carry the same admission to another owner.

For scoped Redis commands, the same connection must acknowledge a trailing PING
with PONG within the original command deadline before reporting completion.
This ordered barrier covers every response in a pipeline, including script-cache
misses. A missing or malformed barrier, lost response, cancellation or worker
panic closes local admission and leaves the durable slot pending. It never
retries an uncertain mutation. This relies on the pinned standalone Redis
command supplier: authority mutations use synchronous commands/scripts, never
background jobs, cluster redirects or commands that change protocol mode.
The barrier proves processing order, not persistence, store identity or rewind
resistance; those qualification obligations remain separate. Existing unscoped
store operations retain their current behavior.

Process restart does not forgive prior uncertain admissions. Startup must bind
its instance and selected stores through the qualified recovery boundary before
serving. A live primary/Redis server restart, rewind, replacement or failover must
refuse old authority until independent history reconciliation and a fresh epoch
complete. A timestamp, process ID, Redis run ID or stored local marker alone is
not sufficient qualification. The store identity supplier and independent current
permanent-history supply remain separate implementation and proof obligations.
