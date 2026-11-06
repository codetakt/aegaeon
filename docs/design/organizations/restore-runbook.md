# Organizations restore and activation

Last updated: 2026-11-05

Status: active plan

Owner: Engineering / Operations

Audience: database operators, security reviewers

This runbook implements the [responsibility rules](recovery-responsibilities.md)
and [selected-generation contract](runtime-generation.md). Aegaeon does not
choose a restore point, perform PITR, reconstruct memory, or replay audit into
business data. Passwords, client secrets, registered keys, ownership and
revocations have the values in the selected database.

## Normal restart and failover

Retain the generation for an ordinary application restart or a database failover
that preserves the operator's committed-state contract. Reconnecting workers
validate the selected database, role and generation. A process restart does not
activate a new generation or reset the external-proof deadlines. Do not run the
activation command merely to clear an error. A failure whose data-loss semantics
cannot be established stays unavailable until operations select a recovery mode.

## Controlled historical restoration

1. Remove traffic and exclude every old writer, worker and maintenance process
   from both the selected target and any former writable primary. Use the
   deployment's credential, network and database controls. A lock on the restored
   database cannot fence a separate former primary. Stop or terminate old SQL
   sessions and verify their absence; a client-side pool close alone is not proof
   that PostgreSQL has processed the disconnection.
2. Preserve available audit/export custody, delivery receipts and the operational
   restore decision independently of the database being rewound. Record the
   operator, deployment, selected restore point, reason, known exported tail and
   any unavailable interval. An unknown tail is an explicit gap, never a claim
   that no activity occurred. Retain post-target events as history of the former
   branch; do not replay them as mutations or automatically revoke credentials.
3. Restore using the database operator's WAL/PITR procedure. Apply the final
   migration and grants if needed, using the [supported upgrade](migration-composition.md).
   Validate the selected writer, schema, restricted runtime role, clock bounds
   and deployment identity before serving. Runtime role authority excludes
   lifecycle activation and migration. Direct PostgreSQL sessions or a qualified
   session-preserving proxy are required; transaction-pooling proxies cannot
   carry the session fence.
4. Generate a fresh generation UUID and operation UUID outside the restored
   database. Read the predecessor from `aegaeon_lifecycle.current`. Run the
   packaged `aegaeon-organization-activate`, or
   [`activate-organizations-runtime.sql`](../../../scripts/operations/activate-organizations-runtime.sql),
   with `deployment_id`, `previous_generation`, `generation` and `operation_id`.
   Review the rollback-default output, then use `commit=true` for the intended
   activation. The prior assertion windows and absolute clock bound are explicit
   `proof_policy` inputs; retain their conservative defaults unless the former
   deployment's smaller bounds are established. Never set `initial_install` for
   PITR, including a restore before Environment creation. Activation refuses a live worker,
   wrong predecessor, reused generation, malformed policy or changed deployment.
5. Read the exact operation from `aegaeon_lifecycle.activations` after commit and
   retain that receipt with the restore decision and audit-gap record. A lost
   command response is unknown completion: inspect this receipt before choosing
   another operation. Never edit the generation or deadlines directly. The
   receipt contains predecessor, generation, actor, operation, activation time,
   policy and each external-proof deadline. Database-local receipts alone cannot
   preserve events intentionally removed by a later PITR.
6. Install the protected version 2 runtime configuration with this deployment,
   generation, primary TLS endpoint/CA and Environment inventory. Start
   `aegaeon-organizations-server`, check readiness and the exact selected state,
   and restore traffic according to the service's operating procedure. Old
   generation sessions, continuations and tokens have no authority in Aegaeon.
   Independent resource servers that validate JWTs offline require their own
   revocation/currentness policy; this application cannot invalidate their memory.

During recovery, affected client assertions and signed Request Objects return
`503 temporarily_unavailable` with no-cache headers until their durable deadlines.
DPoP uses a fresh server nonce and still requires signature, freshness and atomic
single-use verification. Other restored durable authentication methods can issue
new sessions. Default JWT/JAR deferral is 5101 seconds; the DPoP nonce horizon is
1801 seconds. See the [clock derivation](runtime-generation.md#external-proof-activation-policy).
If the clock bound or old-writer exclusion cannot be established, keep the
affected authentication paths offline.

## Audit and external delivery

Keep the consumer's retained event bytes and acknowledgments. Fetch the selected
database's pending outbox again. Stable event IDs and exact content digests permit
deduplication of already exported events; changed bytes for an existing ID must
refuse. Acknowledging a delivery changes bookkeeping, not business authority.
An event retained outside the selected database remains historical evidence even
if it can no longer be acknowledged on the selected branch. Do not delete that
evidence or manufacture a replacement event to make the histories appear equal.

For notifications or other effects observed outside PostgreSQL, reconcile using
the existing business operation/event identity and recipient receipt. A restored
outbox can request a duplicate delivery; the recipient must deduplicate, or the
operator must resolve an uncertain effect before replay. Aegaeon does not promise
to undo an email or another external effect by restoring its database. Undelivered
tail gaps and recipient uncertainty are separate from successful DB activation.

## Offline domain maintenance

Ownership inventory/adoption and inactive import preparation select the current
deployment and generation and hold an exclusive SQL session fence. Online runtime
connections and offline maintenance exclude each other. These commands preserve
their domain receipts and input checks; they do not reconstruct generic database
history. A failed connection releases its database fence, and a later attempt
checks the current selection and domain outcome again. No separate control DB,
Redis seal, per-request pending journal or credential-cutover coordinator is used.

Old control/cutover scripts are retained under `tests/organizations/legacy_operations`
solely for predecessor fixtures. They are not supported operating instructions or
part of the current operations package.

## First-ever installation

For a deployment that has never accepted authentication, the operator may pass
`"initial_install": true` in `proof_policy` to omit the recovery wait. Activation
also requires no selected generation and no Environments. This is an explicit
operational assertion recorded with the receipt, not something inferred from an
empty database. Normal restore uses the default wait even if the selected point
predates initial configuration. Ordinary restarts never use this option.
