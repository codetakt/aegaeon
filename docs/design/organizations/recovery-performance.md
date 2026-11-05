# Organizations runtime performance design

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, operators and reviewers

The user target is **10,000 HTTP requests/second and ordinary-API p99 at most
200 ms**. It is unmeasured. Functional PostgreSQL tests, arithmetic estimates and
formal models do not establish that target.

## Execution path

The selected database owns business state, domain idempotency and current security
state. Runtime physical connections check the selected generation once when they
connect and retain a shared lifecycle lock. Ordinary connection checkout does not
add a lifecycle transaction. Application mutations, audit and domain receipts use
their actual transaction. Atomic code/device consumption and token publication
share one database transaction. Disposable JWKS payloads require current durable
policy; network fetches do not hold a database connection.

There is no independent per-request recovery journal, control-store reservation,
completion seal or application redo stream in this design. The old calculations
for those mechanisms are withdrawn. WAL/PITR, backup throughput, RPO/RTO and
restoration timing belong to the selected database/operations plan.

## Current limits and remaining resource work

| Resource | Implemented bound or behavior | Remaining review |
| --- | --- | --- |
| Ordinary request owners | Explicit configuration, 1–4096 per runtime; immediate refusal when full | Choose a measured deployment budget; configured maximum is not a recommended default |
| Reserved revocation owners | 1–64 per runtime; separate reserved SQL pool within the total configured pool size | Functional saturation test makes a real SQL query through the reserve; no latency claim |
| Snapshot owners | 1–4 per runtime; live authority consumes ordinary capacity too; shared payload budget below | Configure ingress connection/slow-client limits for the deployment |
| SQL pool | At least 2 total connections; reserve is `min(revocation owners, max(1, total/4))`, remainder ordinary | Include replicas, listeners, maintenance and reconnect overlap in the deployment budget |
| Lifecycle admission | Shared session lock per physical connection; immediate activation refusal on conflict | Qualify intended managed topology and session-preserving connection behavior |
| Request execution | Finite owner retained across cancellation and SQL cleanup | Count every owned checkout, worker and transport; failure must not release unresolved work as successful |
| Response materialization | Organizations 64 KiB; general response 16 MiB; process payload accounting 64 MiB with 256 bytes per charged frame | Budget follows byte clones until transport releases them; accounting is not total RSS |
| JWKS | 32 foreground fetches, 32 retained refresh owners, capped cache entries and 64 MiB accounting budget | Accounting bound is not a measured RSS guarantee |
| Cleanup | Indexed batches of 4096, at most 256 batches and 15 seconds per pass | Preserve backlog visibility; test lock contention and steady-state accumulation |
| Administrative inventory | Indexed keyset pages; transactional browser count; at most 4096 rows per browser bulk delete/eviction; OIDC bulk at most 128 events/4 MiB and 1024 client IDs/1 MiB per event | Oversized atomic operations refuse and roll back; operators use bounded individual operations, never silent truncation |

The byte semaphore charges copied, exactly sized payload storage, so a small
slice cannot retain an unaccounted large producer allocation. Charges survive
response-owner completion and release only when the last transport clone drops.
Ordinary capacity and revocation capacity are separate, without increasing the
total configured SQL connection count. Cleanup preserves backlog visibility.

These are application accounting bounds. TLS/socket buffers, headers, connection
count, allocator overhead and upstream body producers are not an RSS theorem.
Deployment ingress must bound connections, header bytes and slow-client duration;
SQL max-connections must include every replica plus listeners and maintenance.
Per-namespace browser creation/count updates serialize; transactions encountering
concurrent cleanup can abort safely and retry as a new request. No global control
journal serializes independent namespaces. Actual throughput and tail latency
remain unmeasured, by user instruction. No larger default pool is justified by
the target alone.

## Measurement model

Measure scheduled ingress to complete validated response, including queueing,
body reading, authentication, database waits, signing, serialization and transport.
Report useful successful completions, overload refusal, timeout and cancellation
separately. A fast refusal does not satisfy the positive-load latency goal.

For capacity estimates, use measured mean service/holding times and actual request
mix. A p99 of 200 ms is not a mean and cannot be substituted into Little's law as
an exact concurrency requirement. Count SQL commands and commits by operation,
not HTTP verb: a DPoP GET can write a replay record. Include connection setup/TLS,
read/lock/commit/cleanup round trips, hot-key serialization and cache misses.

The [qualification plan](recovery-performance-qualification.md) separates the
current PR's bounded functional checks from later high-precision load/provider
qualification. Current results neither guarantee managed-provider behavior nor
close Task 3 product assurance.
