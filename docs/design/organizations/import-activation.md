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

Runtime admission must hold a current witness lease throughout its owned store
work and cleanup. A fence waits for existing leases and refuses new ones before
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
