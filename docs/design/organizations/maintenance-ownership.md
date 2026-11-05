# Organizations maintenance ownership and entry inventory

Last updated: 2026-11-04

Status: historical record

Owner: Engineering / Verification

Audience: runtime, operator and recovery implementers

This successor defines the remaining maintenance part of D01/D03/D06 and
D14/D15. It preserves the adopted runtime, identity and restoration contracts.
It does not authorize activation from a diagnostic receipt or close a proof family.

## Superseded operational design

This page records predecessor behavior and its source-scoped evidence. Its
control-store, paired-seal, generic history-replay and credential-cutover commands
are not shipped or supported by the current implementation. Use the
[current generation contract](runtime-generation.md) and
[restore runbook](restore-runbook.md). Predecessor code retained under test-only
modules is not a production fallback. Historical test results below do not prove
the replacement implementation.

## Executable entry inventory

The server crate currently has one default binary and thirteen files under
`src/bin`. Their production store entry points are listed below. Inspection
still needs explicit credentials, bounded work and cleanup. A read-only label
alone does not establish safe database access. The table is an executable-entry
inventory; internal task/caller and SQL-writer coverage must also be checked.

| Executable | Store entry and effect | Organizations contract and current gap |
| --- | --- | --- |
| `aegaeon-server` | `server_runtime`, ordinary issuer and management | Legacy entry for deployments that have never activated; exclude its launch authority at cutover. |
| `aegaeon-organizations-server` | `main/organization_runtime`, HTTP and background | Mandatory independent configuration; parent before shared work and child before Environment work; packaged startup/shutdown component tested. |
| `aegaeon-organization-delivery` | `server_runtime::deliver_organization_invitation` | Same immutable configuration and parent/child runtime ownership; actual packaged TLS delivery tested. |
| `aegaeon-organization-witness` | `organizations/witness/cli` | Current v12 control catalog; explicit parent/child scope and maintenance role for lifecycle mutations; 17 packaged conditions tested. |
| `aegaeon-organization-history` | `organizations/witness/history/cli` | Independent journal import/inspection and append-only primary restoration; v9 retained parent maintenance owner implemented; packaged nonempty restoration/replay and inspection/failure tested. |
| `aegaeon-organization-import-inspect` | `organizations/snapshot/cli` | Private staging, target or recovery reads under the v9 parent maintenance owner; packaged source inspection/failure tested, recovery acceptance remains. |
| `aegaeon-organization-import-prepare` | `organizations/snapshot/staging/prepare` | Acquires retained parent maintenance ownership before opening the inactive target; packaged native-export preparation/replay/conflict acceptance tested; activation and recovery remain. |
| `aegaeon-organization-store-inspect` | `organizations/store_observation/cli` | Bounded actual store diagnostics; no mutation/activation authority and no nonrollback qualification. |
| `aegaeon-subject-ownership` | `subject_ownership/history/cli` | Legacy preactivation inventory/adoption; excluded by activated reference launch/credential custody. |
| `aegaeon-organization-subject-ownership` | `subject_ownership/history/cli/organizations` | Mandatory v9 maintenance owner; fixed inventory/adoption and pool close before release. |
| `aegaeon-management-init` | `web/management/initialization` | Writes initial global management state; preactivation provisioning only, excluded from activated writer services. |
| `aegaeon-hosted-bootstrap` | `web/management/hosted_bootstrap` | Writes initial runtime/configuration state; preactivation provisioning only, excluded from activated writer services. |
| `aegaeon-observability-seed` | `web/management/hosted_bootstrap/observability_seed` | Writes runtime configuration and an API key; preactivation provisioning only, excluded from activated writer services. |
| `aegaeon-registration-preflight` | dedicated binary's one-connection pool | Quiescent predecessor inspection; must close before cutover and cannot serve as a live writer capability. |

The schema launcher, Atlas migrations, provisioning SQL and database/Redis
administrators are additional privileged entries outside this binary list.
Production admission must account for their credentials and service launch rules.
The HTTP parent/child dispatcher covers handlers only through its observed pools;
background cleanup, configuration monitoring, notification listeners, blocking
Redis workers, streaming replies and cancellation cleanup keep their actual owners
until completion. Direct pool/driver constructors outside that graph remain audit
targets. Test-only fixtures do not constitute production entry authorization.

## One retained maintenance boundary

A control catalog successor must implement one exclusive, durable maintenance
admission per deployment. The caller names the deployment, exact fenced operation
and revision, a fresh operation/worker identity and the bounded maintenance plan.
Admission requires the parent and every child to be fenced and all runtime slots
to be drained. It refuses another pending maintenance operation. This capability
is distinct from a runtime admission, child epoch and user authorization.

Record pending ownership durably before opening a target connection or executing
a child maintenance mutation. Parent prepare/activation and other maintenance
acquisitions must reject pending maintenance. A process lock, long transaction,
lease, child fence or final reread cannot substitute for the durable admission:
control connection loss must not permit a still-running primary writer to overlap
reactivation. No timeout clears the pending record.

The trusted plan identifies whether the operation is independent journal import,
source/target inspection, inactive snapshot preparation, permanent-history
restoration, ownership adoption or schema migration. It fixes allowed stores,
roles, Environment/domain scope, source digests and finite byte/row/time limits.
Runtime login cannot acquire maintenance; diagnostic output cannot enlarge the
plan. Existing custody and append-only/idempotent page contracts remain required.
The plan does not embed passwords or grant arbitrary subprocess execution.

Keep the maintenance owner through actual workers, SQL transactions, blocked
I/O, committed-but-unacknowledged pages, primary connection closure and durable
receipt completion. Normal release requires exact generation/principal/operation,
no remaining child work and acknowledged completion of every opened store resource.
Drop, cancellation, deadline, uncertain COMMIT, failed close and control failure
leave pending ownership. Recovery must establish the real old process and store
connection termination under the existing restoration/custody contract before an
explicit reconciliation; elapsed time and a caller-supplied boolean are insufficient.

The controller's independent custody and nonrollback property remain supplier
conditions. Refuse unqualified replacement/rollback of control history. A new
maintenance operation does not repair missing historical facts or authorize
reuse of deleted subjects, old credentials or epochs.

## Integration and required evidence

Implement this boundary once, then connect history, snapshot and ownership tools.
Do not independently switch their `Control::connect` calls to the current catalog
and expose writers before ownership is retained. Preactivation-only bootstrap and
seed tools remain excluded by the reference deployment's launch/credential custody;
verify the exclusion against an old binary and restored database flags.

The joint candidate must demonstrate normal import/inspect/prepare/restore,
foreign scope and wrong role refusal, concurrent maintenance exclusion, attempted
activation while work is live, cancellation and process death, control and primary
loss, lost COMMIT/receipt acknowledgment, restart and explicit reconciliation.
Bind these cases to exact binaries/catalogs and preserve old-code or stated
mutation controls. Then run the complete startup/HTTP/delivery/background/shutdown
journey with that same candidate. Separate local component tests from supplier
qualification, formal discharge and shipment acceptance.

Task1b retains this implementation and full writer/caller inventory. Task3 retains
ORG-P01/P02/P03/P06/P08/P11/P12/P13/P14/P15 composition and supplier conditions.
The corresponding requirements are ORG-R01/R02/R17/R18/R19/R21/R22/R24 and the
original ORG-G03/G10/G11/G12/G14 gaps; no new atomic obligation count is asserted.

## History coordinator successor

The current implementation candidate adds a v9-only, non-cloneable history owner.
Its fixed command graph retains the exact source-bound plan before acquisition,
then records the acknowledged slot. Import and inspection use that owner's control
connection; restoration opens the primary only while the owner is pending. Every
statement and transaction is awaited and the direct primary is closed before
normal completion. Cancellation, failed restoration or uncertain close leaves the
owner pending. No arbitrary command, completion boolean or digest is exposed.

Input rechecks and the journal/receipt synchronization precede durable completion.
Separate plan, admission, completion and release files make an uncertain final
acknowledgement distinguishable from a local success receipt. The final control
connection close occurs after the acknowledged SQL release; failure at that point
cannot undo a completed release and remains an unconfirmed invocation. There is
then no remaining primary work. Process/store termination after an earlier crash
still needs explicit reconciliation; this change supplies no automatic recovery.

All current Environment, deployment and maintenance connectors require the same
exact v12 catalog and share the bounded role, durability and catalog check. No
constructor accepts v6, v8, v9, v10 or v11 as a fallback. Install v1–v12 in order for a new
control store. Upgrades require every parent and child fenced and drained, all
old processes stopped, and their credentials excluded before activating current
binaries. Historical schemas and manifests remain unchanged for migration and
negative tests. Child registration still requires its explicit registered parent;
connection validation does not create or adopt one.

The joint catalog candidate and current fixtures now use this contract. Full
snapshot acceptance, crash reconciliation, supplier qualification and credential
exclusion still need composed acceptance before shipment. SQL tests and the
conditional transition model do not establish the coordinator's own preconditions
or the supplier's nonrollback guarantee.

## Snapshot command contract

Both snapshot inspection and inactive preparation require `--deployment-id`,
`--parent-operation-id`, `--parent-expected-revision`, `--maintenance-work-id`
and `--witness-ca`. They acquire the same exclusive v9 maintenance owner before
opening any staging or target connection. Source-only inspection still uses a
private staging database; it does not receive target write authority. The retained
plan binds the exact snapshot digest, Environment/domain, target runtime role,
preparation or recovery operation and finite source/time limits. Recovery's child
deployment must equal the parent's deployment; the child operation and revision
remain separate checks.

The fixed coordinator opens and consumes the primary connection. Recovery borrows
the owner's existing control connection rather than creating a second unowned
connection. A successful staging operation must close its primary connection,
then recheck and synchronize the retained input and receipt before releasing the
owner. Failed connection, SQL, cancellation, input recheck or receipt publication
leaves the owner pending. These command changes do not authorize activation or
reconciliation, and require packaged normal/failure tests before acceptance.

## Subject ownership command contract

`aegaeon-organization-subject-ownership` is the activated-deployment entry for
inventory and adoption. Its parent fence arguments (`--parent-operation-id`,
`--parent-expected-revision`, `--maintenance-work-id`, `--witness-ca`, `--primary-ca`) are mandatory.
The operation's `--deployment-id` must be a canonical nonnil UUID and is the same
control deployment; inventory/adoption selects the Environment from the validated
inventory or manifest. The legacy `aegaeon-subject-ownership` retains its existing
preactivation interface and deployment labels. Reference activation must exclude
that legacy executable and its credentials; a primary database flag is not an
acceptable exclusion after restoration. The Organizations entry refuses
`--pre-migration` rather than creating an unowned alternative path.

The new entry validates and retains the exact source/build identity, manifest,
inventory and mapped source bytes before acquisition. Its plan binds their hashes,
Environment/deployment, runtime role, commit intent and finite budget. It then
acquires the same exclusive v9 maintenance slot. A fixed coordinator opens the
primary only after acquisition, keeps the existing locked inventory/CAS adoption,
awaits commit or rollback and closes the one-connection pool before completion.
The entry requires TLS server verification with an explicit primary CA. A failed
connection, uncertain commit, cancellation, deadline, failed close or failed receipt
synchronization retains pending ownership. A successful release is neither
activation authorization nor a certificate of completeness for supplied history.

The operation deadline is 90 seconds, including connection, inventory and adoption;
the packaged process adds a 95-second deadline and a five-second kill grace.
Retained artifacts remain private and non-overwriting. Tests must cover actual
packaged inventory and dry-run/committed adoption, missing/foreign parent and wrong
role refusal, pending-owner exclusion, failed primary connection and cancellation.
The full reference credential/executable custody and restore test remain required
before this entry closes the maintenance/writer inventory.

## Packaged retained-history restoration

The release history coordinator is exercised with an explicitly seeded test
journal containing 258 retained owners and two case-distinct subject reservations.
The actual primary initially lacks these facts. Restricted TLS restoration and
exact operation replay preserve them without creating end users, credentials or
serving authority. Missing parent arguments, a runtime-only control login and
failed primary connection refuse the operation; uncertainty retains the durable
maintenance owner and excludes a subsequent invocation. Both parent and child
authority must remain fenced after these journeys.

The journal is fixture input, not evidence of external history completeness.
The two-page restoration and exact replay run under the current packaged owner.
Crash reconciliation, credential/executable exclusion, source-history adoption,
restore/cutover and independent nonrollback custody still require composed acceptance. Earlier native
multi-page/partial-resume tests remain separately bound component evidence.

## Offline maintenance reconciliation contract

The reference recovery entry is an explicit offline operator operation, separate
from runtime and maintenance credentials. It never activates a deployment. Its
root-owned configuration fixes the deployment, exact maintenance generation,
work UUID and plan digest, all SQL stores reachable by that plan, their retained
cluster/database identities, dedicated old login names, and the system services
that can execute the old maintenance graph. Shared clusters and unlisted login
principals are refused. The recovery administrator is a separate custody domain;
old workers must never possess that credential or permission to alter services.
The complete store/service inventory and credential custody are deployment
premises, not established by a matching identifier or a configuration boolean.

Before mutation, check the exact v12 catalog, durable writable stores, dedicated
unprivileged old logins, distinct control/primary cluster identities, drained
parent/child fences and the exact retained pending maintenance owner. Recheck and
lock the deployment, children and maintenance row for the final transition.
Permanently disable
every old login, erase its password and commit that exclusion on each store.
Never restore these credentials on failure or on successful recovery. Stop the
configured services using their actual service manager and require whole-cgroup
termination; process names, elapsed time and caller-provided completion receipts
cannot satisfy this condition. Refuse unsafe service execution boundaries.

Terminate all old login backends and wait for their actual disappearance. Refuse
any prepared transaction or unexpected client backend. A missing store, failed
stop, lost acknowledgement or deadline leaves the pending slot unchanged and
any completed credential revocations intact. No force-clear option exists.
The fixed maintenance graphs use SQL stores and retained local files; this
operation cannot reconcile runtime, Redis, invitation-delivery or arbitrary
subprocess work. Such pending admissions remain separate recovery obligations.

After rechecking the identities, exclusion and fences, durably retain the actual
observations in a private non-overwriting receipt. Atomically compare and clear
only the selected maintenance slot, storing that receipt's digest; preserve its
generation, work identity and all history. This records stopped work, not a
successful restore or an activation decision. If COMMIT's reply is lost, inspect
the same generation and receipt digest; never acquire a replacement operation
to guess the result. A different pending generation cannot be cleared by replay.
Replacement credentials, append-only history reconciliation, fresh epoch and
cutover acceptance follow separately. No automatic credential provisioning or
serving restart is part of this command.

PostgreSQL's [positive termination timeout](https://www.postgresql.org/docs/18/functions-admin.html)
waits for the backend to exit. Sending a signal without waiting is insufficient;
[NOLOGIN and password removal](https://www.postgresql.org/docs/18/sql-alterrole.html)
are separate from terminating existing sessions. The recovery entry uses both.

The entry has a 120-second whole-operation bound, ten-second SQL statements,
five-second lock/connect bounds, at most eight stores, 32 services and 64 old
logins per store. Its SQL transition and guard-removal model are conditional on
the actual observations and custody premises. Real SQL/service tests, old-worker
reconnect refusal, cancellation, ambiguous completion and exact replay must be
bound to the distributed operator entry before the recovery unit is accepted.

### Operator entry and retained outcome

Build `nix build .#organizations-recovery` and use the resulting
`bin/aegaeon-organization-recovery --config /etc/aegaeon/recovery.json
--output /var/lib/aegaeon-recovery/operation` as the explicitly authorized offline
administrator. The output directory must be new. Configuration, password and CA
files must be root-owned regular files with mode 0600 and one hard link; all
parent directories must be root-owned and not writable by other principals.
Do not place secrets in the Nix store. The command ignores inherited PostgreSQL
settings, uses hostname-verified TLS and refuses non-root invocation. The Nix
wrapper excludes Python environment and user-site overrides.

The version-one configuration has exactly these fields:

| Field | Required value |
| --- | --- |
| `version` | Integer `1`. |
| `maintenance` | `deployment_id`, positive `generation`, `work_id`, exact lowercase `plan_sha256` from the retained owner. |
| `stores` | First the control store, followed by every primary store the fixed plan can reach. |
| Store `kind` | `control` for the first entry; `primary` thereafter. |
| Store `identity` | Retained `cluster` system identifier as a decimal string, `database` name and integer `database_oid`. |
| Store `old_logins` | Complete distinct old login names on that dedicated cluster, excluding the separate administrator. |
| Store `connection` | Explicit `host`, integer `port`, `dbname`, `user`, `password_file` and `ca_file`. No DSN overrides. |
| `services` | Complete dedicated system units named `aegaeon-organization-maintenance-*.service`. |

The current reference command supports one deployment per control cluster and
one application database per SQL cluster (plus PostgreSQL's maintenance and
template databases). It rejects shared clusters instead of disabling unrelated
users. Service units require a non-root user, `KillMode=control-group`,
`SendSIGKILL=yes`, `NoNewPrivileges=yes`, empty bounding/ambient capability sets
and no delegated cgroup. Recovery checks the original cgroup
after stopping the service, including descendant processes, even if the manager
has cleared its current cgroup property. These checks do not establish that an
operator's inventory contains every credential holder or unlisted remote worker.

`reconciliation.json` is synchronized before the SQL transition. `released.json`
records its acknowledged outcome. A failed command must be treated as uncertain,
including failure to publish the second file. Run the same command with
`--inspect` and the original configuration/output directory to compare the
retained receipt against the exact current catalog, generation and SQL digest.
It returns `completed` or `pending` without mutation; altered bytes, another
generation or another plan refuse. `completed` means stopped maintenance only.
If still pending, preserve the old directory and repeat the full recovery with
the same retained owner and a new output directory after correcting the failure.
Never reenable excluded credentials to make a retry succeed.

### Control-host peer boundary

The reference control service permits administrator access only through local
peer authentication. Run the offline coordinator and its fixed maintenance
workers on that control host; primary SQL administration remains explicit TLS.
For the control entry, replace the TCP connection fields with exactly `socket`,
`port`, `dbname`, `user` and `peer_user`. The reference values use the local
PostgreSQL socket and the separate `postgres` database/OS administrator. There
is no password file and no automatic TCP fallback. Explicit TLS control entries
remain supported for independently qualified operator configurations; they do
not satisfy the reference service's peer-only administrator policy.

The single-threaded root coordinator temporarily assumes the selected database
OS identity only while opening the Unix socket, then restores its root identity
and groups in a `finally` boundary. Libpq's
[requirepeer](https://www.postgresql.org/docs/18/libpq-connect.html#LIBPQ-CONNECT-REQUIREPEER)
checks the server's kernel identity; `system_user` must independently report
`peer:<selected-user>`. Trust authentication, the wrong server OS account and
an old worker running as that database administrator are refused. This avoids
introducing a network administrator exception into the reference HBA. Tests
must cover identity restoration on failed connections, actual peer-only HBA,
administrator TCP refusal and the full packaged recovery before this integration
condition is accepted.

Catalog v12 additionally refuses upgrade during an incomplete cutover and adds
maintenance-only locked epoch-intent inspection. See the
[native preparation contract](cutover-credentials.md#native-epoch-transaction-contract).
