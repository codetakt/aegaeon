# Credential replacement before Organizations cutover

Last updated: 2026-11-04

Status: historical record

Owner: Engineering

Audience: implementers and recovery operators

## Superseded operational design

This page records predecessor behavior and its source-scoped evidence. Its
control-store, paired-seal, generic history-replay and credential-cutover commands
are not shipped or supported by the current implementation. Use the
[current generation contract](runtime-generation.md) and
[restore runbook](restore-runbook.md). Predecessor code retained under test-only
modules is not a production fallback. Historical test results below do not prove
the replacement implementation.

## Ordering and authority

This refines ORG-R18/R19/R21, ORG-G10/G11 and ORG-P08/P11/P12/P13/P14.
The current-state comparison does not make excluded worker credentials usable.
Keep the independent deployment and all children fenced, with every pending
runtime and maintenance owner reconciled, while replacing credentials. The
current source remains retired. Only the separately restored destination and
control-store serving identities receive replacements; recovery administrators
and fixed NOLOGIN ownership groups are not renamed.

The operator must first validate current content, native catalog and complete
current history, and explicit key/credential compatibility. Replacing SQL login
credentials does not rotate or validate encrypted application secrets, OAuth
client credentials, passwords or key-store decryptability. Those remain distinct
checks. A later fresh epoch invalidates old OAuth roots; SQL password replacement
alone does not establish that property.

## Retained plan and independent progress

The coordinator retains one canonical, root-owned mode-0600 `plan.json` in a
mode-0700 directory, outside backup restoration. It contains new random SQL and
Redis passwords, the exact SCRAM verifiers, role OIDs/attributes, old/new names,
store identities and the configuration digest. The file, directory and parent
directory are synchronized before registration. Creation is exclusive; an
existing, partial or missing registered plan never permits generating different
credentials. Reading rejects symlinks, multiple hard links, permissive ownership
or modes, changed configuration, noncanonical bytes and digest mismatches. The
secret plan is bounded to 4 MiB, two independent SQL stores and 64 roles per
store. It must not be placed in the Nix store, public receipts or logs.

Control schema v11 retains only the secret plan's SHA-256 digest, the exact
deployment/fence operation and revision, fence-state digest, administrator,
monotone step and receipt digests. A unique index admits one unfinished operation
per deployment; at most 4,096 retained operations are admitted. Neither runtime
nor maintenance roles have journal table access. The installation refuses any
active/prepared parent or child and every pending runtime/maintenance owner.
Existing schemas and their manifests are immutable migration inputs.

The ordered saga is fixed as follows. Each intent is durable before the named
external effect; each following observation is retained after checking the
actual supplier. The journal is not a distributed transaction.

| Step | Retained state |
| --- | --- |
| 0 | Plan registered before any credential mutation |
| 1 | Full current source and destination comparison retained |
| 2–3 | SQL replacement intent; exact disabled replacements observed |
| 4–5 | Token preparation intent; exact empty, disabled token supplier observed |
| 6–7 | Native validation intent; catalog/history/keys and new-principal validation observed |
| 8–9 | Epoch preparation intent; new parent and all child selections observed |
| 10–11 | Configuration publication intent; one complete protected configuration observed |
| 12–13 | Activation intent; exact parent and children activated and bound |
| 14–15 | Selected worker start intent; actual admission and old-writer exclusion observed |
| 16 | Final receipt retained; operation complete |

The preparation-prefix journal covers steps 0–7. It requires the same live drained
fence and exact plan at every transition. A repeated immediately preceding
transition returns only its identical receipt; conflicting receipts, skipped or
older predecessors refuse. Lost replies require reading the journal and actual
affected stores. The SQL and Redis preparation helpers leave all credentials
disabled. This prefix stops before epoch preparation. The following sections
describe the separate coordinators through step thirteen and the remaining
serving/recovery work; the allocated schema range alone is not implementation
evidence.

The conditional SMT model checks ordering, exact-plan/fence requirements,
nonactivation and receipt replay, with two omitted-guard counterexamples. Actual
SQL tests also detect removal of the plan comparison. These are component checks,
not automatic refinement of filesystem durability, native validation, independent
store supply or the whole cutover procedure.

## Preparation command

The root preparation coordinator accepts a private configuration containing the
existing restore `inspection`, complete control/destination role `names`, the
new Redis user/command profile in `redis`, and a version-one `preparation` object
with `retired_token` and `destination_token` connection/identity inventories.
Both token connections use verified TLS. The retired process identity must equal
every retained parent/child token checkpoint. Its credentials stay excluded and
no other client may remain. The destination must have a different process identity
and pass the empty-store/profile checks above. Neither connection description is
accepted as a substitute for those actual observations.

The `organizations-recovery` package installs
`aegaeon-organization-cutover-prepare --config FILE --directory DIRECTORY`.
Run it explicitly as the offline root operator. Reuse both the exact configuration
and the same protected directory when resuming; do not delete `plan.json` or
replace a registered plan. Successful output reports step five and
`activationAuthorized: false`. All old credentials stay retired and the new
credentials remain disabled. The command has no enable or force option.

The coordinator uses one private directory and one independently registered plan.
Before every invocation advances the prefix, it rechecks the stopped services,
current source, destination contents, old token exclusion and exact fence. Its
first comparison receipt is synchronized before advancing step zero; subsequent
comparisons must preserve the same content and store identities. An interrupted
SQL replacement is reconciled independently in each store using the retained
role OIDs and verifiers. An interrupted Redis preparation repeats only the exact
retained OFF profile and persistence operation. Every intent precedes its effect.
The whole invocation has a finite deadline. Failure retains the plan, journal
and all already acknowledged exclusions; it never clears a record or activates.
At step five it reports only prepared, with activation unauthorized. Native
validation and steps six onward are separate from this command's result.

The `organizations-recovery-integration` package provides the Linux/systemd CI
runner. The required DB Integration job runs retained-secret recovery, actual
cutover preparation and the omitted-token-drain negative control using the
packaged operator. Sandboxed SQL/Redis/model checks remain separate; a passing
CI fixture does not qualify production storage or credential custody. The same
runner also exercises native validation against an actual full backup restored
into a third SQL cluster, with separate retired and fresh TLS Redis instances.
Its forward-recovery case adds a fourth SQL cluster and third TLS Redis instance:
it reconciles an actual interrupted owner, rejects the pre-write backup, copies
the current accepted data, and completes another full cutover with new dedicated
workers. The old session and ungranted reconciliation capability remain denied.

## Durable private receipts

The Linux offline operator requires a protected, durably provisioned directory,
a filesystem supporting `O_TMPFILE`, file/directory `fsync`, and the actual process
`/proc/self/fd` mount. It writes and synchronizes an unnamed mode-0600 inode before
exclusively linking the complete file to its final basename, then synchronizes
the directory before acknowledging or registering dependent control state.
Existing files, symlinks and hardlinks are never replaced. Unsupported storage,
failed writes, linking or synchronization refuse without a weaker fallback.

Process loss before linking leaves no partial final file; loss after linking
leaves a complete file whose exact bytes must be reconciled. A directory-sync
failure is an uncertain publication, never permission to overwrite or regenerate
registered secrets. This ordering follows the Linux
[unnamed-file publication contract](https://man7.org/linux/man-pages/man2/open.2.html)
and separate [directory synchronization requirement](https://man7.org/linux/man-pages/man2/fsync.2.html).
The regression exercises actual child termination at four publication stages,
concurrent exclusive publication, injected storage errors and the original
partial-file negative control. It does not qualify physical power-loss behavior,
rollback resistance, or filesystem/device honesty; those remain supplier premises.

## SQL login replacement

Use new, explicit login names and freshly generated random passwords. Under an
exclusive offline transaction, rename each excluded login to the new name while
preserving its role OID, exact object grants, ownership and role membership.
This preserves the existing least-privilege configuration without constructing
broader replacement grants. Keep the renamed role NOLOGIN while recording the
new verifier. Recreate the old name as a NOLOGIN, passwordless role with no
memberships, members or owned objects. Retain that name permanently; it cannot
be recycled by ordinary administration. Historic textual principal receipts
remain unchanged and cannot authorize completion under the new name.

The complete old/new mapping, actual source role OIDs and store identity must be
retained before mutation. New names must be absent and pairwise distinct, and
must not overlap old names, administrators or fixed ownership groups. Refuse
privileged old principals, active sessions, prepared transactions, unlisted
logins and unsupported background writers. Commit every replacement for one
store together. Failure rolls back that store's changes, not earlier acknowledged
store exclusions or other stores' completed replacements.

Generate and retain new secret files under root custody before the SQL change;
never place secrets in public receipts or command arguments. Use libpq's explicit
SCRAM-SHA-256 verifier generation and retain the exact verifier for reconciliation.
A lost commit acknowledgement is resolved by the old tombstone, new role OID,
new verifier and unchanged privilege graph. A new attempt must not generate
another password or reinterpret a partial mapping as success.

The packaged internal SQL primitive currently checks role identity, role
attributes, verifiers and inert retired names. It leaves new roles NOLOGIN and
has no command-line enablement path. Its coordinator must still retain the
password/verifier plan before mutation, hold the independent fence, exclude
concurrent administrative changes, and revalidate the actual full privilege
catalog under the new names. Role-OID preservation alone is not that validation.

## Native credential inspection and bounded SQL validation

The distribution's `aegaeon-organization-store-inspect credentials --root-cert
FILE --environment-id UUID --issuer URL` checks the actual hostname-verified
primary connection configured by `AEGAEON_ORGANIZATION_OBSERVATION_DATABASE_URL`.
It uses the ordinary runtime namespace/catalog validator, then a repeatable-read,
read-only transaction and the serving implementations for upstream-secret
decryption and runtime-key construction. Key envelope scope, private/public-key
correspondence and supported provider/algorithm combinations are checked. Active,
next and retiring runtime keys are inspected; revoked keys remain retained data.
An AWS-backed OIDC key requires the compiled provider and its actual constructor
to succeed. This point-in-time check does not qualify future external availability.

Active local-password and client-secret hashes must use the existing Argon2id
profile (version 19, memory 19456, time 2, parallelism 1, 16-byte salt, 32-byte
hash). This validates format compatibility without claiming knowledge of a
password, resetting a credential or evaluating attacker-chosen Argon2 costs.
Unsupported formats require explicit remediation before cutover. Each of the
four collections is bounded to 100,000 rows, 64 MiB and 64 KiB per row/value;
runtime keys additionally have a 1,024-row limit. SQL statements have five-second
deadlines, the transaction twenty seconds and the command twenty-five seconds
inside the existing thirty-second distribution wrapper. Success follows rollback
and connection closure, reports only counts/identities and cannot activate.

The internal SQL validation lease retains its exact store, selected new role
names and sixty-second absolute expiry before enablement. It preserves the
original OIDs, privilege graph and retained SCRAM verifiers. Cleanup commits
NOLOGIN first, waits for actual termination of the selected roles' backends and
rechecks the exact replacement profile. Expiration alone does not prove backend
exit; password expiry also does not replace verified transport/authentication
configuration. A changed lease, verifier, finite original expiration or role
attributes refuses. Exact cleanup can be repeated after an uncertain response.
Unbounded password lifetimes normalize PostgreSQL's NULL/infinity representations
and are restored using supported `VALID UNTIL 'infinity'` syntax; finite lifetimes
remain exact. The tool does not write PostgreSQL system catalogs directly.
See [PostgreSQL ALTER ROLE](https://www.postgresql.org/docs/18/sql-alterrole.html).

The `organizations-cutover` package composes these checks into steps six and seven
through `aegaeon-organization-cutover-validate --config FILE --validation-config
FILE --directory DIRECTORY`. It reuses the original preparation configuration and
protected plan directory. The separate version-one validation file contains exact
`control` and `primary` endpoints (`host`, `port`, `database`), a `token` endpoint
(`host`, `port`), the original role selectors `control_runtime`,
`control_maintenance`, `primary_runtime` in `roles`, and the private
`root_cert_file`, `key_encryption_key_file` and complete `environments` list
(`id`, `issuer`). There may be at most 64 distinct Environments; their IDs must
equal the independently retained child inventory. This file supplies neither
success assertions nor a replacement native executable.

Before any lease, the coordinator synchronizes a binding of the exact inputs,
CA and key digests and immutable Nix wrapper/binary identities, then records the
native intent. It uses the original retained replacement secrets for credential,
history and runtime diagnostics in each namespace. Only required SQL identities
receive a sixty-second login lease. The fresh Redis identity is temporarily ON
only for the runtime diagnostic. SQL NOLOGIN and actual backend exit, and Redis
OFF, ACL persistence and actual client exit, must all be confirmed afterward.
No supplied successful process exit substitutes for these store observations.

Every attempt is retained before enablement, including the exact lease expiration.
After a crash, the next invocation disables and drains incomplete attempts before
rechecking the original fence and current source/destination contents. It never
clears pending work or regenerates a secret. At most 512 attempts may be retained;
exhaustion refuses instead of deleting history. Step seven retains the complete
native/history receipt after fresh comparison and exclusion checks. Repetition
reruns those checks and permits only monotone WAL advancement under identical
incarnations, facts, configuration and binaries. Both command and process have
finite ten-minute deadlines. All failures preserve exclusions and the retained
plan; neither timeout nor successful validation activates a worker.

The native history diagnostic uses only the fixed history reader under the new
control maintenance identity and read-only queries under the new primary runtime
identity. It requires exact drained parent and child fences, the compiled
catalogs, separate physical SQL stores, and the adopted Environment/issuer. It
checks every retained history page using the native chain decoder. The root
coordinator separately compares every permanent owner and byte-exact subject
reservation with the primary in one repeatable-read snapshot, bound to the same
head. Exact total counts exclude additional primary facts; the runtime identity
does not gain direct access to protected history tables.
The sealed head and parent fence are checked again before closing both links.
This fixed diagnostic does not import, restore, reserve or clear pending work;
therefore it creates no durable maintenance owner. Its result remains a
point-in-time observation until the offline coordinator rechecks the live fence,
all current data and actual connection exclusion. The same 25-second command
and 30-second distribution deadline apply; oversized or slow histories refuse.
This does not replace a complete current authorization-state comparison with
permanent ownership facts.

## Token store and activation

The destination token store starts empty with a new independent store identity
and process incarnation. No old Redis token/session/refresh data or credentials
are imported. New serving credentials have the explicit product command/key
profile and cannot administer ACLs, load modules or change store configuration.
The old Redis store and every old credential remain excluded.

The internal Redis preparation step checks a different process incarnation,
verified-TLS administrator identity, standalone/durable AOF configuration, an
explicit ACL file, and all sixteen logical databases empty. Only the independent
administrator, disabled default user and one exact replacement user may exist;
other clients, module/replication suppliers and unexpected users refuse. The new
user stays OFF, with a single retained password hash, no channel rights, no ACL
selectors and an explicit subset of the product command inventory. All keys are
within this dedicated instance; this is not a shared Redis service profile.
`ACL SAVE` must succeed. A lost acknowledgement can be reconciled by an explicit
same-profile operation; neither an in-memory read nor a new random password is
accepted as evidence of the preceding operation's persistence. This step does
not enable serving, qualify native command coverage or retire the old store.

After native validation under the new SQL/Redis identities, pin actual new store
observations and prepare a fresh parent epoch and fresh child epochs through the
independent CAS protocol. Bind the final source/history/configuration/artifact
and credential-replacement receipts. Publish one complete protected startup
configuration, activate its exact selection, and start only its selected worker.
A crash or lost reply retains the operation and fences admission until the actual
phase is reconciled. No flag asserting that validation succeeded can replace the
live checks. Serving startup and rollback remain separate implementation work
until the complete sequence, failures and accepted-write preservation are exercised.

## Following epoch and activation phases

The following phase contract separates implemented offline transitions from
remaining serving/recovery work. Its presence alone is not verification evidence. After step seven, retain a new
root-protected epoch plan before advancing to step eight. It binds the original
fence snapshot, exact native/current-content receipts, complete child inventory,
fresh parent/child epochs and new logical primary/token identities. Reuse those
same identifiers after uncertainty. Never regenerate epochs for a registered
intent or reselect an earlier physical store.

Prepare the parent and every child, and pin actual retained destination
connections, in one bounded transaction on the independent control store using
its separate maintenance identity. Serving stays fenced; SQL/Redis credentials
are leased only to the owned fixed observer while workers remain stopped. Store
observations come from actual verified connections; serialized
operator assertions cannot construct an observed-store handle. The transaction
must either preserve the original fences or select the complete prepared set;
partial child preparation is not a valid completion. SQL cleanup still confirms
NOLOGIN and actual backend exit after the bounded maintenance operation.

An uncertain COMMIT must reconcile the exact selected epochs, operation IDs,
revisions, digests, checkpoint identities and complete child set before step nine.
The old fence guard cannot simply be disabled when preparation changes it. Use
phase-specific comparison against the retained original and intended successor,
with no pending runtime/maintenance owner and no unexpected current selection.
Recheck the retired source against its original independent checkpoint and full
current data, the destination, services, credential exclusions and history head.

Before activation, publish one complete, root-protected worker configuration
containing only the selected destination, fresh serving credentials and exact
new parent/child selections. Keep all service identities disabled and workers
stopped through publication. Bind its bytes, executable, service identity and
credential custody in the independently retained receipt. Parent activation,
all child bindings and child activation must form one control-store transaction;
no worker may start under a partially active inventory. Any change, uncertainty
or failed cleanup remains closed for explicit reconciliation.

Only after that exact activation is observed may the selected serving identities
be enabled and the selected service start. Check actual admission, complete
namespace selection, old-writer exclusion and durable progress before the final
receipt. A later rollback is another fenced forward cutover from the then-current
accepted data, with fresh credentials and epochs. It never restores an earlier
snapshot that discards later accepted writes or revocations.

### Native epoch transaction contract

The fixed native epoch preparer consumes one root-retained JSON intent (at most
256 KiB), whose exact file SHA-256 is already registered as the eighth cutover
receipt. Version 1 carries `deployment_id`, `cutover_operation_id`, a `parent` object
with `operation_id` / `revision` / `selection`, and 1–64 `children`. Each child
contains `environment_id`, independently expected `issuer`, and a `transition`
object with the same operation/revision/selection fields. The intent also binds
`stores` containing the prior actual primary/control PostgreSQL and token Redis
observations; native SQL incarnation must match with nondecreasing WAL, and token
incarnation/database must match exactly. Every selection names
a fresh nonnil epoch, common fresh primary/token IDs, and exact source/history/
acceptance digests. The coordinator binds these to the validated current-data
and native receipts before registering the intent; the file alone is not a permit.

Control catalog v12 adds maintenance-only `cutover_selection` to lock and observe
the registered intent, parent, and complete ordered child set. It refuses a
missing/different digest, wrong step, pending work, mismatching parent operation
or revision, or more than 64 children. Ordinary service roles still have no table
access; runtime cannot invoke this function. Upgrade preserves prior catalogs
and refuses an incomplete cutover as well as active or pending authority.

The native preparer uses a checked maintenance login and actual retained primary
and token connections. It verifies namespaces, distinct SQL clusters and the
complete selection, then prepares parent and children and pins their actual store
checkpoints within one control transaction. It commits only the complete set;
errors or interrupted connections roll back uncommitted changes. A lost COMMIT
reply is reconciled using the same intent, selections and physical store identity.
This phase neither activates authority nor enables service credentials. Root
exclusion, independent current-content validation, input custody and the later
configuration/activation checks remain required caller conditions.

### Offline epoch coordinator inputs and restart

`aegaeon-organization-cutover-validate --prepare-epochs` continues an existing
step-seven operation using the same configuration and private plan directory.
It retains `original-state.json` before registration; its canonical object digest
must equal the independent journal's original fence digest. `epoch-binding.json`
binds the secret plan, original snapshot, complete content comparison, native
validation receipt and configuration, and both the immutable preparer wrapper and
native binary. Each selection's acceptance digest is this binding file's SHA-256.
The source digest is the canonical object digest of the complete comparison's
`content`. Child history digests are the native-validated sealed history digests;
the parent history digest covers the ordered complete list of those history heads.
These are evidence bindings, not an assertion of production supplier qualification.

The coordinator retains exactly one `epochs.json` (256 KiB maximum) with fresh
UUIDs, then registers its exact bytes as receipt eight. Later invocations require
all retained files and original derivations; missing files after registration are
never regenerated. Before and after native execution it checks all three actual
SQL stores, old and new Redis stores, stopped services, complete current content
against the **original** source checkpoint, and the independent history. The new
destination checkpoint cannot replace the original source's freshness authority.
Only WAL advancement within the exact retained physical incarnation is allowed.

When a recovery, inspection or preparation entry provisions its output directory,
it synchronizes both that directory and its parent before connecting to stores.
Receipt-file synchronization alone cannot persist the new directory's name.
Either synchronization failure stops the entry before dependent store work;
this software ordering is separate from qualification of physical persistence.

Native attempts share the existing finite budget of 512 attempts. The exact
60-second SQL leases are retained before enabling the maintenance and observation
identities; no serving worker starts. The fixed native process has a 60-second
outer deadline and 1 MiB combined output budget. Cleanup confirms SQL NOLOGIN and
backend exit plus Redis OFF, ACL persistence and client exit. Restart first cleans
any incomplete attempt, even when COMMIT prepared all epochs. It then reconciles
the same intent; it never selects another epoch after an uncertain result.

`epoch-prepared.json` is retained before receipt nine. At step nine, current state
and original data are checked again against that receipt without repeating the
native mutation or enabling another lease. Missing, changed or inconsistent
receipts fail closed. This entry stops at prepared authority; configuration
publication, activation and worker admission are separate subsequent phases.

### Protected startup publication and selected workers

The separate, explicit `--prepare-startup <settings.json>` operation runs
after step nine. Its version-one worker settings enumerate at most 32 system
services: exactly one server for each selected issuer. Authenticated invitation
delivery uses the server's existing observed API. The separate finite, stdin-driven
delivery CLI is not treated as a long-running daemon or started without a request.
Every unit
has a fresh dedicated name, an explicit nonroot OS account, and a fixed packaged
entry. Server settings additionally name the selected Environment and an explicit
IP address and port. No caller-provided executable, shell fragment, environment
override, unit fragment or arbitrary command line is accepted. The existing
native startup parser must check issuer-host ambiguity before publication.
It also returns the exact host selector used by the actual server, including
IDNA, host-case and default-port handling. The coordinator binds that returned
selector into the launch input instead of interpreting the URL in a second
library. The configured issuer string and Environment identity stay unchanged.

Worker accounts differ from every retired worker and store-administrator account.
Before starting, the coordinator checks that no process under a selected account
exists outside the selected service groups. These checks operate under explicit
root custody of account creation, unit configuration and process launch; they do
not establish isolation against an independent host administrator or kernel.

For each service, retain a complete runtime selection document and launch input
under the original root-private plan directory. Runtime documents carry the new
runtime-only control login, primary login, empty replacement Redis identity,
the parent selection and the complete ordered child/issuer selection. They never
contain the maintenance login. The launch input binds the Environment, listener,
validated encryption-key bytes and fixed runtime document. The certificate bytes
must equal those accepted during native validation. Delivery trust is explicit
and follows the existing bounded trust schema; an omitted trust list grants no
outbound delivery destination. Changing it requires a new bound configuration.

Use systemd `LoadCredential=` for these root-owned source files. Runtime documents
refer to the selected service's `/run/credentials/<unit>/root-cert`, and the fixed
launcher reads its credential files before `exec` of the immutable packaged server
entry. The launcher constructs a fresh environment with only the
defined bootstrap inputs; it never inherits database, loader or shell overrides.
Secret bytes are not placed in unit text, argv or logs. This uses systemd's
[per-service credential copies](https://www.freedesktop.org/software/systemd/man/260/systemd.exec.html#LoadCredential=).
The product's existing environment-only encryption-key loader receives its value
inside the owned process; filesystem credential delivery does not claim that the
application has eliminated secret process-environment exposure.

Retain the worker manifest before journal step ten. It binds exact credential
source bytes, runtime/launch document hashes, native executables and wrappers,
unit names, accounts and the full generated unit text. Publication creates only
new protected files and fresh unit names; it never overwrites a conflicting file
or rewrites an existing worker. Synchronize files and containing directories,
reload the service manager, and compare actual loaded unit properties, executable,
credential sources and stopped state to the manifest before step eleven. A partial
publication resumes only the exact retained manifest; missing or changed registered
secret inputs are a recovery condition, not permission to generate another plan.
Generated fragments reside in `/run/systemd/system`; they are deliberately not
enabled at boot. The durable manifest and secret sources remain in the supplied
protected plan directory. After a host restart, recreate a missing fragment only
from that exact retained manifest while authority and logins remain excluded.
This is runtime unit reconstruction, not regeneration of secret inputs. No claim
of power-loss durability is made for `/run` or an ephemeral plan directory.

Publication currently completes journal steps ten and eleven while authority
stays prepared and every serving login stays disabled. It checks the complete
current store/history inventory again, validates each generated document with
the native parser, and binds actual typed systemd `ExecStart` and `LoadCredential`
properties. Replays reject conflicting bytes, drop-ins, prior starts or processes
under the selected accounts. Real root/service tests interrupt publication after
the first fragment, resume the same manifest, refuse missing retained inputs and
reconstruct a missing runtime fragment. These tests establish neither serving
activation nor qualification of a production host's custody and persistence.

Native activation is separately registered at step twelve. It consumes the epoch
intent and exact published worker manifest, validates complete runtime documents
and actual retained destination connections, then activates the prepared parent,
binds every child and activates every child in one control transaction. Only the
entire original prepared inventory or the entire exact active inventory is a
valid replay state. Journal step thirteen requires exact actual selection,
checkpoint, association, current-data and worker-exclusion reconciliation.

The root entry is `--activate-epochs <settings.json>`, using the same
settings and retained directory as publication. Before journal step twelve,
retain `activation.json` with the epoch, manifest and publication-receipt hashes,
the complete ordered runtime-file hashes and the fixed native artifact binding.
The native `--activate <activation.json>` mode is distinct from pure startup
checking and offline preparation. It requires the registered step-twelve digest
and the maintenance principal that prepared every selected checkpoint. It checks
the actual SQL/Redis connections and native startup selectors again. All parent
and child transitions and associations share one control-store transaction.
An already active complete inventory is reconciled without trying to rebind an
active child. Partial prepared/active inventories, changed associations or pending
work are refusals. Completion never starts a server or enables a serving login.

Reserve the revision capacity needed for both preparation and activation before
preparing an epoch. Retain previous child-to-parent epoch associations alongside
the original checkpoint evidence, and verify that adding the new associations
does not remove or replace earlier ones. Associations retain and validate the
preparing principal and their original registration timestamp; neither field is
discarded when comparing the complete stored row. The native and root sessions
may serialize `timestamptz` with different offsets; compare the exact UTC instant
at PostgreSQL microsecond precision while preserving every other binding field.
Reject malformed, timezone-free or finer-than-microsecond input. An interrupted
activation retains its original intent and expires/disables its temporary validation logins before
reconciliation. The native/root regression exercises an actual child-update lock
timeout that rolls back the parent and new association, process loss after COMMIT,
exact restart, local-offset/UTC timestamp agreement, missing retained inputs,
historical association deletion and replay without additional login leases.
The root journey provisions two Environments through the production configuration
writer and exercises complete history validation, worker publication and native
activation for both. A final-child timeout also rolls back the already updated
parent, preceding child and associations. The separate SQL inventory fixture
uses two children with manufactured checkpoint inputs. Neither fixture qualifies
production suppliers or establishes full-capacity serving acceptance.

Step fourteen records the exact serving-credential and service-start intent.
Only the selected runtime SQL and Redis identities are enabled; maintenance and
retired credentials remain excluded. Start only the manifest's services, verify
their actual executable/credential custody and every server's live readiness
through the selected boundary, and check old-writer exclusion before step fifteen.
An interrupted start first stops the selected services and disables the selected
identities, retains any pending work, and reconciles actual state. It cannot reset
epochs or discard accepted writes to repeat the earlier offline phases. Final
step sixteen records the complete result only after all start conditions hold.
Serving startup and interrupted-start closure are implemented by the packaged
`--start-workers` operation and exercised with actual supplied services. A new
complete forward cutover after closure remains a separate recovery obligation.
The [serving and recovery contract](serving-recovery.md) fixes interrupted-start
closure, accepted-write preservation and the distinct aborted journal state.

The root cutover path accepts at most 32 Environments, consistently from native
validation settings through complete worker publication. The SQL/native inventory
primitive's separate 64-child bound does not expand this operator contract.

The conditional `cutover_activation.smt2` model checks complete-inventory
commit, required intent/principal/store conditions, nonactivation of serving
credentials and preservation of prior associations. It retains a lost-reply
witness and a counterexample for independently committing the parent. Atomic SQL
durability, exact digest comparison, root custody and implementation refinement
are explicit premises. This model does not discharge product assurance; actual
transaction-failure, recovery, caller and supplier evidence must be composed.
