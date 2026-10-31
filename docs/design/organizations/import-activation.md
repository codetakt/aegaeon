# Organizations inactive import and restore boundary

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

## Required separation

This implementation contract refines ORG-R17/R18/R19/R21 and ORG-G10/G11,
contributing to ORG-P02/P06/P08/P10/P11/P12/P13/P14/P15. The target inspector is
an observation, not an activation capability. A successfully checked file must
remain inactive until the independently retained authority state accepts it.
The independently fenced activation mechanism remains forthcoming. Inactive
preparation is under implementation and has no activation capability. Its
inspection tests do not qualify the activation or witness mechanisms.

All object UUIDs, exact external identifiers, subject ownership, tombstones,
revision/incarnation history, audit and command receipts remain preserved.
An inactive import must not silently rename records, merge conflicting ownership,
normalize Unicode, union permissions, or turn a deleted dependency into a current
registration. Ordinary snapshots contain no usable OAuth, invitation, password
or upstream credentials. Credential compatibility/reset is a separate gate.

## Independent authority witness

The selected authority state must live outside the primary and token-store
restore domain. Its contract is a durable linearizable compare-and-swap register
per Environment, with an unpredictable nonnil epoch UUID, immutable deployment
identity, selected primary/token-store identities, monotonically increasing
revision and one of `fenced`, `prepared`, or `active`. Revision exhaustion refuses
all transitions. Old epochs are permanently retired, including aborted imports.
A caller-supplied serialized record is never a witness.

An actual supplier must establish nonrollback durability and authenticated access
independently of the restored stores. A second ordinary database is not by itself
evidence of this contract. The integration must reject missing or unqualified
supply, inaccessible current state, identity mismatch and incomplete transitions.
There is no local-cache or administrator allow fallback. Normal runtime, migration
and witness administration use separate credentials and minimum capabilities.

Runtime admission must retain a durable pending witness admission throughout
its owned store work and cleanup. This record has no permission-granting expiry;
loss of the caller or its witness connection must leave it pending. A fence waits for existing leases and refuses new ones before
it reports success. Response cancellation cannot release a lease while a store
operation can still commit. Lease loss is a closed admission class until explicit
reconciliation; it cannot be treated as a successful fence. Storage deadlines,
request capacity and operator process deadlines apply to this supplier too.

Original authorization records capture the admitted epoch. Selected tokens,
refresh lineage, invitations/challenges and temporary administrative grants retain
that epoch as protected internal state. Every current use compares it with the
fresh witness state and selected store identities. Missing or retired epoch data
refuses; it never inherits the current epoch. Public object IDs and standard OIDC
subject representations do not change. Any exposed profile field must receive
its own versioned wire contract and compliance evidence before introduction.

## Inactive preparation and cutover

1. Authenticate the explicit maintenance operation and identify the expected
   Environment, domain, source artifact, current witness revision and store
   identities. The source cannot select these parameters.
2. Fence the Environment in the witness and wait for actual admitted work to
   finish. Retain the operation UUID and transition receipt before changing any
   primary authority. Do not restart an uncertain operation under a new identity.
3. Retain the final source snapshot after the writer fence. Recheck complete
   format, source graph, current independently retained ownership history,
   credentials and destination dependencies under the exclusive boundary.
4. Prepare destination records in an inactive scope. Normal readers and mutators
   must reject that scope, including configuration actions that ordinarily enable
   a domain. Preserve historical states separately from serving admission.
5. Compare old and new decisions on the declared supported input domain, check
   migration completeness and durable audit/receipt preservation, and obtain the
   required acceptance receipt. Retire the old adapter and all old root authority.
6. Publish exactly one selected destination and a fresh epoch through witness CAS.
   Only that epoch/store pair may serve. Failure or a missing acknowledgement
   leaves the operation fenced until the recorded state is reconciled.

These are durable saga phases, not a distributed atomic transaction. Each phase
has an operation identity, expected predecessor revision, exact artifact hashes
and a replayable result. A conflicting replay refuses. Recovery observes both
stores and the witness before selecting the one permitted next transition; it
never infers commit from a timeout, returned socket or missing response. Cleanup
must preserve incomplete evidence and cannot silently delete accepted changes.

## Restore qualification

A supported backup restore starts with the external fence and always retires the
old epoch. Reconcile restored permanent history with the independently retained
current history before serving. The live runtime also needs a qualified way to
detect an unexpected store rewind or replacement; operator instructions alone do
not establish that guarantee. Primary timeline/position or Redis process identity
are diagnostic inputs, not standalone nonrollback witnesses or complete rollback
proofs. Their limitations, privilege boundaries and actual failure modes must be
resolved before production activation is exposed.

Test real isolated primary, token store and witness failures; lost replies before
and after each durable phase; concurrent cutovers; exact-ID conflicts; replay;
old-root rejection; retained revoked ownership; and normal recovery. Bind those
results and transition/refinement proofs to the actual distribution and supplier
configuration. A finite passing test or a transition model alone does not close
the composite proof obligations or authorize shipment.

## Inactive preparation implementation boundary

A new maintenance-only preparation entry accepts an explicit operation UUID and
exact independently expected snapshot digest. It validates format, source graph,
compiled catalog and current target references in a read-only transaction, then
copies organization-owned records into a new, disabled destination domain.
Existing domain/object conflicts refuse; identity, permanent history, client,
provider and operator dependencies are compared and never overwritten.

This preliminary inactive copy may precede the final external writer fence. The
reference observation is deliberately not a freshness guarantee across its write
transaction. Activation must take the independent fence, retain the final source,
revalidate current dependencies and compare the exact candidate before proceeding.
A changed source or dependency cannot be accepted merely because preparation once
succeeded. No activation entrypoint or automatic normal-configuration escape is
provided by this preparation component.

The entire destination copy and its operation receipt commit in one transaction.
A crash before commit leaves no destination rows. A lost commit acknowledgement
requires the same operation UUID and exact source; replay returns the retained
receipt after complete input and current catalog checks. Conflicting operation,
source or scope refuses. An operator must preserve the original source artifact;
the receipt is not a substitute for it.

A private import marker forces the destination domain disabled. Ordinary runtime
configuration and mutation paths reject it. Database guards also reject changes
to held domain and child records by normal runtime authority. The marker cannot
be cleared through ordinary configuration. The fixed maintenance writers have
no direct table grants for callers and no activation operation. Dependencies are
not re-created by this component; broader identity/credential migration remains
separate.

All disclosed historical fields, IDs, incarnations, revisions, tombstones, audit,
outbox state and receipts are copied. The source enabled value is retained in the
operation record, while serving remains disabled. Capability hashes are absent
from ordinary export; delivered invitation/challenge/request rows receive fresh
unusable digest values solely to preserve storage invariants. Their historical
state is preserved, but no old secret is transferred or made usable. Cutover must
retire original authorization and reauthorize; digest replacement alone does not
establish epoch revocation.

The parser's 64 GiB total, one-million-row section, 256 KiB row and ten-row page
bounds still apply. Maintenance connections retain finite statement, lock, idle
and one-hour transaction limits. A separately bounded process must own file I/O
and cleanup. Failed preparations preserve evidence and never silently delete an
existing candidate or retry under a different operation identity.

The distribution command is `aegaeon-organization-import-prepare`. It uses the
same private source, output custody, explicit database, verified TLS and binary
source binding arguments as the inspector, plus mandatory `--operation-id`
and `--target-runtime-role`. The inspector remains read-only. Each preparation
attempt uses a new private output directory while retaining the same operation
identity for reconciliation. Database success with missing local success output
is an uncertain acknowledgement, never a reason to overwrite or choose a new ID.
The protected operation record retains the authenticated maintenance and session
principals; credentials are not recorded. Its operator history must accompany
final migration acceptance and is separate from the ordinary source snapshot.

## Selected control-store protocol

The control-store implementation uses a separately provisioned PostgreSQL 18
cluster and a dedicated database/schema, outside both primary and Redis restore
procedures. It is not installed by the primary schema migration. This selects a
concrete CAS supplier, not a claim that PostgreSQL alone establishes nonrollback
storage. Independent durability, restore exclusion, authenticated role separation
and current permanent-history supply remain deployment qualification obligations.
A missing qualification prevents production activation; test fixtures cannot
supply a production qualification.

Each Environment has one serialized control row, retained operation identities,
permanently consumed epoch UUIDs and 64 admission slots. A slot contains a positive
monotonic generation, epoch, work UUID, authenticated login and pending
state. Acquisition requires the exact active epoch and selected store identities,
and takes a free slot. Release matches all of those fields plus slot/generation.
There is no timeout-based release, lease stealing, takeover on connection loss or
administrative delete entrypoint. A delayed release cannot clear a reused slot.
A pending work UUID cannot be acquired twice, even by the same authenticated
login. Unlike a transition receipt, an admission is permission to execute once.
A lost acquisition reply leaves pending state for qualified reconciliation; a
retry never obtains a second handle or infers that no work began. Completion of
an already released exact slot remains idempotent until its generation changes.
All exhausted counters refuse new work; the control revision reserves its last
value for a terminal fence. One control database permits 1,024 Environments and
65,536 retained transition operations per Environment, plus one terminal fence.
Capacity exhaustion cannot truncate history or prevent that final fence. Maximum occupancy refuses admission before store work.

Fence changes the current state before waiting for pending slots. New admissions
then refuse. The fence is drained only after every actual owner explicitly closes
its store work and releases its exact slot. A crashed owner leaves the Environment
closed; a separate, qualified reconciliation must establish store completion
before recovery. No generic force-clear option is part of this protocol.

A maintenance transition has an operation UUID and exact predecessor revision.
Preparation requires a drained fence and permanently consumes a fresh nonnil epoch,
binding exact primary/token-store identities, final source/history digests and
acceptance evidence. Activation checks that same prepared operation and selection
under the row lock. Abandoning preparation fences it and never returns its epoch
to the allocator. Concurrent operations cannot both select an authority. Replays
must match the entire original request and current phase; a historical successful
fence is never reported as a currently drained fence after activation.

The runtime login can read the current selection and acquire/release its slots;
it cannot prepare, activate or fence authority, write the tables, assume their
owner, or call private helpers. A separate maintenance login can perform the fixed
transition operations but receives no arbitrary table writes. Startup verifies
these privileges and the compiled control-store schema. The runtime adapter owns
a verified-TLS connection with finite acquisition/statement/lock/transaction
budgets and closes on uncertain transport. It forces synchronous commit, requires
read-committed transactions and checks the live server's fsync, full-page writes,
primary role and writable transaction state. Any missing condition refuses.
These settings are necessary for acknowledged durable pending work, but do not
establish independent nonrollback storage or permission to override a restore. A connection disappearing never removes
a pending admission. No restored primary row or serialized claim can substitute
for a live control-store observation.

The successor catalog query also enumerates every rewrite rule on a control
relation, including disabled, replica-only and always-enabled rules. The selected
schema contains none, so any such entry refuses both service roles before a
control handle is returned. Its definition and enabled mode use the existing
finite entry/output bounds; historical schema and catalog files remain unchanged.
[PostgreSQL rewrite rules](https://www.postgresql.org/docs/18/sql-createrule.html)
can add writes before the original command executes, independently of triggers.
For example, a rule on authority updates can clear pending slots during fencing.
The real-database regression verifies that effect and that the changed catalog
refuses connection. It also covers every rule enable mode and normal reconnection
after removal. These checks contribute to ORG-R19/R21, ORG-G10/G11 and
ORG-P08/P11/P12/P13/P14; they do not discharge those composite obligations.
Deployment administration must exclude concurrent schema mutation while runtimes
serve. Startup correspondence does not establish protection from a privileged
administrator changing objects after the check.

This component precedes runtime integration, independent-history reconciliation
and physical store-rewind detection. Their contracts above remain required;
the existence of these fixed control functions does not expose production cutover.

## Owned work and completion evidence

A durable witness admission follows every owner of its primary/token-store work
and protocol/pool cleanup. A response timeout, dropped task, TCP EOF or successful
transport shutdown is not a completion receipt. In particular, SQLx PostgreSQL
close sends Terminate without waiting for the server; failed protocol draining
must close local admission and leave the witness pending even if close succeeds.
Only confirmed ReadyForQuery/rollback and completed pool cleanup can contribute
to normal release. A cancelled worker retains these obligations through its
cleanup owners. Production callers must also account for their token-store work;
a primary-connection handle alone is insufficient for whole-request completion.

The witness work coordinator acquires a fresh durable slot before selected-store
work. Its local admission is shared with checked-out connections and their owned
cleanup. Explicit completion waits at most 30 seconds for all other retained
owners to finish and requires the local class to remain open, then completes the
exact witness slot and closes its control connection. An error, cancellation,
panic or lost coordinator leaves durable pending state. It never clears that
state from a destructor or after a wait expires. Slot release still requires the
caller's complete token-store and detached-worker ownership; this adapter does
not yet establish the HTTP/token caller integration or a qualified cutover.

## Control-store operator command

### Pending-work inspection

Before reconciliation can establish actual store completion, an operator needs
the exact admissions that remain pending. Catalog version two adds the
maintenance-only `pending` observation to `aegaeon-organization-witness`. It
returns one current state and its pending slots under the same authority-row
lock. Each slot identifies the Environment, slot number, positive generation,
epoch, work UUID and authenticated runtime principal. The client also derives
the diagnostic store label specified in [runtime epochs](runtime-epochs.md)
from those retained fields and the deployment. At most 64 slots exist;
completed slots are omitted. An empty observation is not an activation receipt.

The runtime login cannot inspect these identities, read tables, or impersonate
maintenance. The new operation cannot release a slot or mutate any authority,
operation, epoch or admission. A read timeout leaves all pending state intact.
Its output is sensitive operational metadata, to be retained with the private
recovery record. It contains no credentials or reusable completion handle.

Install `db/organization-witness/schema-v2.sql` after version one using the
separate provisioning authority. This forward addition preserves every earlier
schema byte and stored record. The client checks the exact version-two catalog;
an old or altered catalog refuses. This implements the observation prerequisite
of ORG-R17/R18/R19/R21, ORG-G10/G11 and ORG-P06/P08/P11/P12/P13/P14. It does not
establish current independent history, store completion, restore qualification,
permission to clear uncertain work or composite proof discharge.

`aegaeon-organization-witness` exposes `status`, `pending`, `initialize` and `fence`.
Initialization creates a fenced Environment; neither command prepares or activates
serving authority. Every invocation supplies explicit Environment/deployment IDs,
role class and a trusted CA file. The control endpoint is taken only from
`AEGAEON_ORGANIZATION_WITNESS_DATABASE_URL`; it must name a TCP host, login and
database. Ambient PostgreSQL connection settings, socket aliases, query-based
role/destination overrides and TLS downgrades refuse. The runtime login cannot
initialize or fence even if it calls SQL directly.

A fence requires its retained operation UUID and expected revision. Status and
fence output include the current phase and pending count; only `fenced` with zero
pending operations is drained. Lost output must be reconciled with live status
and the same operation, never by deleting slots or inventing another identity.
Authenticated maintenance principals and transition timestamps remain in the
protected operation ledger. Operator output is nonsecret scope metadata, not an
activation credential. Capture it in the deployment's private operations log.

The distribution imposes a 30-second process deadline followed by a five-second
termination grace. The native client independently bounds connection, SQL and
close waits. An interrupted invocation may have committed its transition; the
control-store record, not the process exit status, decides recovery. Production
activation remains unavailable through this command.
