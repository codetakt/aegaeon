# Refresh-grant revocation and coordinated upgrade

Last updated: 2026-10-03

Status: current implementation baseline

Owner: Operations

Audience: operators and maintainers

Aegaeon revokes an entire refresh grant when any known refresh generation is
revoked or refresh-token reuse is detected. Earlier and later access tokens from
that grant become inactive, even with `retainRefreshChain=false` and after old
refresh records and neighbor indexes expire. Separate authorizations for the
same client and subject remain separate grants. Revoking one access token keeps
its narrower scope. RFC 7009 §2.1 and RFC 9700 §4.14.2 govern these relationships.

`retainRefreshChain=true` additionally requires the recorded parent to remain
usable. With the option disabled, an earlier access token may survive ordinary
rotation; grant revocation still denies it. Every Aegaeon online resource,
UserInfo and introspection decision consults the independent grant authority.
An independent resource server that only verifies a JWT signature offline does
not learn this decision; it needs an online revocation decision or its separately
chosen token-expiry policy. No new public JWT claim is introduced.

## Stored authority and failure handling

Stored refresh tokens, access tokens and bearer metadata share an internal
`refresh_grant` object with `version: 1` and a random opaque `id`. Initial atomic
publication allocates a collision-checked identity; descendants preserve it.
The token-store v3 prefix owns `refresh-grant:v1:<digest>` records containing the
reference, original client and subject, revoked flag and exact retention deadline.
The `expiry:refresh-grant:v1` sorted set rounds deadlines upward; bounded cleanup
compares the exact current record before deletion. `refresh-grant-cleanup-cursor:v1`
advances bounded scans past malformed records, whose unknown-retention bytes are
preserved. No SQL migration or configuration toggle is added.

Every descendant commit checks active authority and extends retention atomically
with publication, including when a writer resumes after its operation lease
expires. Retention reaches the maximum committed refresh/access/metadata expiry;
changing token lifetime does not shorten it. Grant revocation commits before
bounded physical cleanup (4,096 refresh visits and 16,384 child tokens). Missing
indexes or cleanup-budget failures cannot restore authority. Test snapshot
replacement cannot overwrite the independent decision.

Missing, malformed or unsupported grant authority and inconsistent references
are inactive. Redis failures remain errors. Introspection establishes caller
visibility before exposing grant-store errors: an unrelated caller receives
`active:false`; an authorized caller receives no-cache HTTP 503 for unavailable
storage. Revocation also returns no-cache 503 for a storage/cleanup failure, but
denial may already have committed. A lost reply has the same uncertainty; retry
idempotently and investigate storage without restoring an old active record.
Success does not promise complete physical deletion. Authorization-code publication
consumes its code before irreversible token writes; a later Redis failure requires
fresh authorization, not replay of the same code.

## Upgrade and inventory

This is a deliberate storage compatibility change. Legacy refresh records have
no trustworthy durable identity: they cannot rotate or mint descendants and
must reauthorize. Legacy access/metadata with `refresh_parent` but no reference
is inactive under both retention policies. Missing or inconsistent metadata
cannot establish an independent grant. Consistent rootless access/metadata with
no refresh parent remains eligible under its existing policy. There is no guessed
backfill, automatic root creation or authorization to delete production records.

1. Schedule the reauthorization window and preserve the existing Redis bytes,
   configuration and executable identities through the deployment's private
   backup procedure. Do not publish raw token records or credentials.
2. Stop admission and drain **all** token-store readers and writers, including
   background jobs, before counting or activating the new binary. A scan of a
   changing namespace is not an exact inventory.
3. Using an account restricted to `SCAN`, `GET`, `TIME` and `SELECT`, run the
   read-only helper with the exact configured v3 token-store prefix. `SELECT`
   is required when the Redis URL selects a nonzero database. The helper reads
   `AEGAEON_TOKEN_STORE_REDIS_URL`, invokes `redis-cli`, and emits counts only:

   ```sh
   python3 scripts/operations/count_legacy_refresh_grants.py \
     --prefix 'EXACT_CONFIGURED_TOKEN_STORE_V3_PREFIX'
   ```

   Any `redis-cli` error or stderr diagnostic, including a warning, makes the
   inventory incomplete and stops count output. Correct authentication and
   database-selection permissions before retrying; do not use fallback counts.

   Record all legacy refresh counts and live dependent bearer/access counts,
   the scan time, prefix, backup identity and expected reauthorization window.
   A dependent bearer record whose access bytes are absent is reported separately
   by the count difference. Counts describe retained records, not successful use;
   no liveness or product-assurance conclusion follows. Investigate malformed
   records privately. No helper command mutates Redis.
4. Start all readers and writers on the compatible release, verify their artifact
   identities, and reopen admission. Confirm new authorization and refresh work,
   family revocation denies earlier generations, and independent grants survive.
   Existing legacy-dependent sessions must authorize again.

Mixed old/new readers or writers and rolling rollback are unsupported: old code
ignores the new denial. Rollback needs a separately planned coordinated
invalidation of affected generations and another full drain; running an old
binary against preserved active tokens is not a rollback procedure. Keep originals
private and immutable. This upgrade does not authorize production cleanup or
change the separate code-replay/client-deletion revocation triggers.
