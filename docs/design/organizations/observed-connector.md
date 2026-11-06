# Observed Organizations connection construction

Last updated: 2026-11-04

Status: active plan

Owner: Engineering

Audience: implementers and security reviewers

This component refines ORG-R17/R18/R19/R21, ORG-G10/G11 and
ORG-P08/P11/P12/P13/P14. It constructs the three metadata links consumed by
`Work::start_observed` and `Work::start_http_observed`. It introduces no enablement
setting, qualification assertion, production route or activation command.

The constructor takes explicit control, primary and token endpoints with separate
CA files. It reads each regular CA file once, at most 1 MiB, and retains the bytes
in the connection configuration. Replacing a path after construction cannot
change the connector's captured additional CA bytes. Opening the actual descriptor
uses nonblocking mode before its regular-file check, so a FIFO without a writer
refuses instead of stopping the executor at open. Symlinks to regular CA files
remain supported; the check and read use the same opened descriptor. This is not
a wall-clock guarantee for arbitrary or unavailable filesystems; the runtime
supplier must qualify filesystem availability as well as the network transport.
PostgreSQL always verifies
the hostname and chain; the pinned SQLx 0.8.6 Rustls implementation also retains
its bundled WebPKI roots. This is not exclusive trust in the supplied CA file.
Redis requires authenticated `rediss` with an explicit database and verified
TLS. Endpoint aliases, startup overrides and ambient PostgreSQL settings refuse.
No endpoint, password or full connection configuration is logged or serialized.

Each connection attempt uses a fresh runtime-only control connection and checks
the exact catalog and runtime privileges. The constructor additionally requires
the expected nonnil Environment UUID and exact issuer (at most 16,384 bytes).
The actual primary connection must pass the existing runtime namespace entrypoint
and independently compiled catalog checks for that Environment and issuer. The
same connection is retained for observations after the read-only transaction
rolls back. The maintenance-only internal preflight is not granted or called.
The existing server startup validator shares this connection-level implementation;
its namespace permit, generation and issuer checks remain unchanged. Both PostgreSQL links
must expose the required builtin observation under explicitly provisioned minimum
privileges. They must report different cluster identities; separate databases on
one cluster refuse. This is a necessary separation check, not proof of independent
storage or nonrollback durability. Transport qualification must bind the entire
accepted trust set, including SQLx's bundled roots; a wrong-private-CA test alone
does not prove CA exclusivity. Redis uses the actual process and database
observation. All links are owned by the resulting observed connection bundle.

One attempt has a 20-second deadline enclosing connection and preflight work;
individual operations retain their five-second deadlines. There is no reconnect,
retry, role escalation or unobserved fallback. Callers must take existing local
capacity before polling this connector through the owned Work constructor, and
retain that work through response production and cleanup.

## Mandatory parent construction (2026-11-03 successor)

The deployment parent protocol supersedes the earlier standalone Environment
serving constructors described below. The supported serving API is
`deployment::dispatch::Dispatcher`, with a fixed deployment selection and a
validated Environment registry. Each entry owns the parent before shared work,
then the associated child before Environment work. Ordinary and HTTP closure
construction is deferred into that admitted scope; periodic passes acquire fresh
owners and hold no slots while idle. Actual observed cleanup precedes child and
parent completion. A confirmed SQL statement refusal can drain the parent;
uncertain acquisition or wrong-role acquisition retains its pending owner.

Remove the unreleased single-Environment `dispatch::Dispatcher` and standalone
`work::Work` begin/start constructors. They cannot satisfy the current catalog's
mandatory parent contract and must not be presented as usable serving APIs. The
control catalog continues to revoke standalone acquisition; a test-only client
retains explicit privilege-denial regressions. This changes no shipped wire ID,
URL, token field, database identity or SQL grants.

The Environment-aware diagnostic connector and `ObservedConnections::inspect`
remain available for bounded store inspection, without serving or activation
authority. They do not replace the deployment connector or qualify nonrollback
supply. Earlier standalone API descriptions below are historical composition
notes; the parent API in this section governs serving integration.

## Fixed dispatch boundary

The dispatcher owns one immutable connector, Environment/deployment scope and
selected epoch/store tuple. Construction rejects nil identifiers, a connector
for another Environment, and malformed lowercase SHA-256 selection digests.
This is configuration validation, not authentication or supply qualification.
Each operation still acquires its own live durable admission and checks actual
store observations; no successful previous call becomes a cached permit.

Dispatch first rejects an existing async or synchronous Organizations scope,
then takes the existing process-wide capacity for the requested class without
waiting. Failure starts neither a connection nor the operation. Ordinary and
revocation operations have the existing 30-second budget; the snapshot class is
available only through the owned HTTP boundary with its existing finite stream
budget. The caller, not request input, selects the class. It must use revocation
capacity only for revocation and snapshot capacity only for read-only exports.

The operation is supplied as a closure. The dispatcher invokes that closure
only inside the admitted, observed task scope, after all metadata links and the
current witness selection have passed. It retains the same scope through the
operation's future, HTTP body production and confirmed cleanup. Dropping even
an unpolled result handle cannot cancel already dispatched work. Failure,
uncertain completion or panic leaves the existing fail-closed admission rules
in effect. No reconnect, alternate selection or unobserved execution is offered.
Captured values must not start work before dispatch or in their destructors;
detached children still require explicit owner propagation.

This component supplies the common entry used by startup, HTTP and supervised
background mounting. The background scheduler dispatches each finite pass
separately without holding admission while idle. The
[integrated distribution](implementation-status.md) exercises those callers;
building a dispatcher alone does not certify complete writer coverage.
Production activation, supplier qualification and the restore/cutover conditions
below remain required.

The component cannot authorize production mounting. Qualification still needs
independent durability and restore-domain evidence, actual transport/role and
capacity conditions, complete writer coverage, current history, credential
recovery and cutover under the import/restore contract. Equality or difference of
observed cluster identifiers cannot establish these additional premises.

Acceptance includes explicit destination/CA pinning, invalid or downgraded TLS,
wrong runtime role, primary preflight refusal, same-cluster refusal, actual
independent-cluster success, lost metadata links and capacity/cancellation
composition. Actual TLS execution and deployment qualification are distinct from
parser tests; unexecuted conditions remain open.

The standard PostgreSQL inventory also exercises the connector's actual primary
validation entry with a separately initialized, restricted runtime database.
It requires successful normal observations while the maintenance-only preflight
remains inaccessible, rejects another Environment or issuer, and checks refusal
and fresh-connection recovery after revoking the runtime entry's permission.
The test owns its database and restores no unrelated shared privileges. The
ordinary fixture supplies its own local transport; these cases supplement the
separate packaged TLS and cluster-separation checks, without claiming their scope.

The existing operator diagnostic gains a `runtime` mode. It consumes the three
already documented witness/observation endpoint variables and the explicit CA
bundle path, plus required `--environment-id` and `--issuer` arguments for runtime
mode only. It constructs the same runtime-only connector, reports the primary
and Redis observations only after all metadata links close, and always reports
`activationAuthorized: false` and `nonrollbackQualified: false`. It acquires no
admission, changes no selection, and never clears pending work. This mode is for
preflight of the actual connector and does not install it in the server.

## Finite background passes

An explicitly observed runtime configuration monitor uses one fresh ordinary
dispatch for each revision check and any resulting client synchronization.
The configured interval retains the existing 1–3,600 second bound. The first
pass waits one interval; missed ticks are skipped instead of creating a burst.
Idle waiting holds neither local admission nor a durable slot or metadata link.
The operation closure is constructed inside the live admitted scope, just as
for a request. Each pass retains the existing 30-second complete-work deadline.

A restart request prevents the next pass. If it arrives during a pass, the
scheduler waits for that pass's actual completion before returning. Dropping
the scheduler's waiter cannot cancel its already dispatched worker. Failed
admission or completion stops this scheduler and its existing supervisor requests
a graceful restart; it never retries outside the observed boundary. A caller
already inside an Organizations scope cannot start a periodic scheduler.

The observed monitor constructor requires the dispatcher, loaded configuration
and AppState to identify the same Environment, and refuses before spawning on
a mismatch. It is an explicit integration entry for qualified startup assembly;
it does not replace the ordinary executable's startup path by itself. It must
replace, not accompany, that deployment's ordinary periodic monitor and raw
notification-driven checks. Notification listener ownership, cleanup passes,
startup hydration, global management scope and complete production mounting
remain required. This change establishes no supplier qualification or composite
proof discharge; it contributes to the R/G/P mapping above.

## Observed cleanup integration

The observed cleanup entry uses the same finite-pass dispatcher and validates
the existing cleanup interval and Environment before spawning. Each pass runs
the existing expiration, cache cleanup and stale-command reconciliation work.
The owned scope selects Environment-scoped command reconciliation; it must not
fall back to the global reconciliation query. Blocking children retain the work
owner through their real completion, including after a component timeout.

Any component failure or counter-read failure makes the observed pass fail and
the supervisor requests restart. The ordinary scheduler retains its existing
logged-error behavior. Both entries share the cleanup operation so that adding
a cleanup component cannot silently omit it from the observed path. The observed
scheduler waits one interval before its first pass and skips missed ticks.

Qualified assembly must replace its ordinary cleanup scheduler, bind every
participating store to the selected restore domains, and retain the work until
all children and connection cleanup finish. This entry does not authorize
global management mutations or qualify those stores. Startup, notification and
HTTP mounting and complete writer/supplier qualification remain separate gates.

## Startup reads and notification checks

ORG-D03/D04/D05 integration retains the caller's observed work during initial
configuration loading, namespace validation and per-client authorization
observation. The same admitted connection owns the repeatable-read transaction,
rollback/commit and actual pool return. A scoped configuration result must match
the selected Environment before its policy or keys can be consumed. Namespace
validation and client observation reject a foreign Environment before opening a
primary connection. An unbound local permit cannot substitute for an epoch.
Ordinary callers without Organizations work retain their existing behavior.
These changes close these raw-read paths; they do not construct a production
runtime or establish that all remaining startup reads are covered.

The notification listener treats PostgreSQL LISTEN as a wakeup hint only. It
holds no epoch while idle or while establishing its hint connection. Connecting
and registering LISTEN share a ten-second deadline; shutdown can cancel that
connection attempt. Transport reconnect retains the existing bounded exponential
backoff. A lost connection is surfaced by SQLx `try_recv` with implicit eager
reconnection disabled, so every reconnected listener performs a fresh authority
check even if notifications were missed. Neither a notification payload nor a
successful hint connection grants authority. Endpoints and payloads are not logged.

The observed listener entry dispatches the initial check, the check after every
reconnect, and every relevant notification check through a new finite Work.
Admission/check/completion failure ends that listener and its supervisor requests
restart; it never falls back to an ordinary check. A restart during an active
check waits for its actual completion. Dropping the production waiter does not
cancel the dispatcher's retained worker. The periodic monitor remains mandatory:
notifications can be lost and cannot establish present authority by themselves.
Qualified startup must select exactly one complete set of monitor, notification
and cleanup schedulers; these constructors are not automatic enablement.

Single-Environment admission is deliberately unchanged. Global management and
cross-Environment writes still require a separately implemented admission contract
that fences every affected Environment and prevents races with enrollment of a
new Environment. Acquiring the issuer's ordinary work cannot satisfy that contract.
No global bypass, deployment-qualification boolean or narrowed feature claim is
introduced to permit mounting before ORG-D01–D06's joint acceptance conditions.
