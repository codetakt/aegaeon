# Organizations offline runtime recovery

Last updated: 2026-11-04

Status: historical record

Owner: Engineering / Verification

Audience: implementers, operators and reviewers

## Superseded operational design

This page records predecessor behavior and its source-scoped evidence. Its
control-store, paired-seal, generic history-replay and credential-cutover commands
are not shipped or supported by the current implementation. Use the
[current generation contract](runtime-generation.md) and
[restore runbook](restore-runbook.md). Predecessor code retained under test-only
modules is not a production fallback. Historical test results below do not prove
the replacement implementation.

## Responsibility revision — 2026-11-05

The [adopted recovery rules](recovery-responsibilities.md) are the successor
design. The mechanisms and results below describe the existing implementation
and its historical validation, not a requirement to preserve volatile state or
implement application-level WAL/PITR. The [workplan](recovery-workplan.md) tracks
the replacement; legacy guards are test-only after their consumers migrated.

## Required boundary

This contract refines ORG-R17/R19/R21/R24, ORG-G10/G11/G12 and
ORG-P08/P11/P12/P13/P14. It extends the
[maintenance recovery boundary](maintenance-ownership.md) to runtime work.
It must not turn an interrupted write into a claimed successful write or a
current store-progress observation. The offline coordinator implements this
reconciliation boundary; it cannot activate a deployment or establish production
inventory, custody or nonrollback qualification by itself.

The deployment and all child authorities must already be fenced. Retain their
exact revisions, operation identities, pending slot generations, worker/principal
bindings, selected store identities and interrupted observations before excluding
credentials. An exclusive offline operator must establish the complete dedicated
store and worker inventory. A receipt supplied by an untrusted caller is not an
observation. Sharing a control deployment, SQL cluster or Redis instance with
unlisted workers is unsupported and must refuse before pending release.

The ordered recovery is credential exclusion, actual whole-service termination,
SQL/Redis connection termination, persistence and scope revalidation, then exact
pending-generation reconciliation. Each acknowledged credential exclusion remains
in force after any subsequent failure. Retain a durable private receipt before
the control transaction and resolve a lost acknowledgement by inspecting current
state. Preserve history, tombstones, epochs and unfinished store observations;
never fabricate a successful `finished_wal`. Serving still requires a fresh epoch,
history reconciliation, new credentials and the separate cutover acceptance.

## Redis exclusion component

Use one explicit verified-TLS administrator connection with a separate password,
finite socket/reply/process budgets and no reconnect or retry. Require the expected
actual `run_id` and selected database, standalone primary, no replicas/external modules,
always-fsynced AOF and an explicit ACL file. The instance has exactly the listed
old users (including `default`) and the separate authenticated administrator.
Reject worker ACL selectors, expanding command categories and commands outside
the concrete runtime command inventory; workers cannot administer ACLs, configure
the server, load modules or create replication paths. The pinned Redis 8.10.2
distribution's built-in `vectorset` registration (version 1, empty path and
arguments) is the only accepted module entry; workers receive none of its commands.
Unknown or externally loaded module inventories refuse.

Reset each old user's passwords, keys, channels and commands and persist the ACL
file before proceeding. [ACL SETUSER](https://redis.io/commands/acl-setuser/)
does not itself close every existing connection; explicitly terminate old-user
clients and check the actual client inventory. An unexpected administrator client
refuses completion. [ACL SAVE](https://redis.io/commands/acl-save/)
must acknowledge persistence; missing/error replies retain uncertainty. The pinned
supplier must preserve the file-and-directory synchronization implemented by
[Redis ACL persistence](https://github.com/redis/redis/blob/8.10.2/src/acl.c).
Supplier qualification includes restart and failed-save observations, not only
an in-memory ACL readback.

After [CLIENT KILL](https://redis.io/commands/client-kill/), require
only the operator connection, unchanged server identity, no AOF buffer or pending
fsync and no rewrite in progress. This component does not use `WAITAOF` as a
cross-client persistence acknowledgement. Unfinished operations may have committed
before termination; their data is retained and checked by subsequent reconciliation.
No rollback, successful response or authority activation is inferred.

The RESP2 reader bounds encoded replies to 1 MiB, arrays to 4,096 elements,
nesting to eight levels and lines to 4 KiB before accepting allocations. Each
socket operation has a five-second timeout. Any protocol, transport or command
failure invalidates the connection permanently. Root credential custody and the
outer process deadline remain the coordinator's responsibility.

## Acceptance obligations

Exercise actual TLS Redis with retained AOF/ACL files, normal and queued work,
client termination, restart, old-credential refusal, extra users/clients,
privileged selectors/commands, persistence failure, wrong identity and outage.
Retain a mutation control that detects an omitted exclusion guard and bounded
protocol fault peers. Combine those results with actual SQL/control and service
termination, concurrent/replayed recovery and losses before/after control commit.
The conditional recovery model must retain incomplete progress and require all
external observations; a model result is not supplier or implementation proof.

## Operator configuration and retained result

The packaged `aegaeon-organization-recovery` accepts configuration version 2 for
runtime recovery. Version 1 remains the distinct maintenance recovery operation.
Both require root-owned private configuration, explicit destinations, protected
credential files, a new private output directory and the bounded offline process.
Install the current catalog v1 through v16. Versions 15 and 16 require an offline,
drained, fenced upgrade; an existing pending incident must be reconciled before
that upgrade. See [store continuity](store-continuity.md) for the corresponding
primary migration and preparation. The v11 addition requires the
drained fence and adds the [cutover journal](cutover-credentials.md). The v10 addition retains recovery
receipts without changing preceding schema files or granting either service role
direct access. Apply it offline with parent/children fenced and no maintenance
owner; interrupted runtime pending records are preserved for reconciliation.

| Field | Required value |
| --- | --- |
| `version` | Integer `2`. |
| `runtime.deployment_id` | Exact independently selected deployment UUID. |
| `runtime.recovery_id` | Nonnil UUID retained for this recovery and all its retries. |
| `runtime.fence_operation_id` / `fence_revision` | Exact current parent fence, never inferred from a timeout. |
| `runtime.state_sha256` | SHA-256 of the canonical current runtime inventory. |
| `stores` | Exactly one control and one primary, using the maintenance connection/identity format. |
| `services` | Complete dedicated `aegaeon-organization-runtime-*.service` or maintenance unit inventory. |
| `token.identity` | Actual selected `run_id` and database number (0 through 15). |
| `token.connection` | Explicit `host`, `port`, `user`, root-owned `password_file` and `ca_file`. |
| `token.old_logins` | All old users, including `default`; separate from the administrator. |

`--runtime-inventory` retains the fenced state and its digest without changing
control records or excluding credentials. It uses the same explicit configuration;
the initial `state_sha256` can be 64 zeroes for this read-only operation. Review
the retained selection and insert the observed digest into the final configuration.
The subsequent mutation compares the complete snapshot before and after exclusion.
Every pending owner must belong to an excluded principal and the selected epoch;
all checkpoints must select the actual dedicated primary and token stores.
An unrelated login, changed generation, other physical store or incomplete fence
refuses. The inventory is bounded to 32 MiB; receipt capacity is 1,024 per deployment.

The runtime result and private receipt digest commit with the child-then-parent
pending updates in one control transaction. The recorded prior state preserves
all interrupted observations, generations and epoch history; it never fills in a
missing completion observation. `--inspect` resolves the original private receipt
against the retained recovery record without repeating mutations. After a failure
before this transaction, use the same recovery identity and configuration with a
new output directory; existing exclusions remain in force. Never overwrite an
earlier receipt or treat a lost local output as permission to use a new identity.

The local composition test executes the packaged root entry with independent
PostgreSQL clusters, local control peer authentication, verified primary/Redis TLS
and a real system service with a child process. It exercises ACL-save failure,
retained parent/child pending state, exact retry, interrupted SQL/Redis transactions,
read-only completion and old-credential refusal. Removing token-client termination
leaves an old client and fails the identical final client assertion. Separate
SQL tests and conditional models cover rollback, replay and unchanged unfinished
progress. Native catalog upgrades, deployment supply and complete restore/cutover
acceptance remain separately required; these results do not discharge a composite
Organizations proof obligation.

Catalog v12 additionally refuses upgrade during an incomplete cutover and adds
maintenance-only locked epoch-intent inspection. See the
[native preparation contract](cutover-credentials.md#native-epoch-transaction-contract).

Catalog v13 adds atomic activation inspection; v14 retains the distinct aborted
serving result and frees the unfinished cutover slot only after confirmed closure.
Both upgrades require the drained fenced state, with no incomplete cutover.
See [serving recovery](serving-recovery.md) for accepted-write preservation and
the separation between closing an interrupted start and a new forward operation.
