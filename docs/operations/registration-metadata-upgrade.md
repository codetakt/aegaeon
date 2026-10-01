# Registration metadata consistency upgrade

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Registered values and compatibility

New registrations that omit `grant_types` receive only `authorization_code`.
Request `refresh_token` explicitly when needed; existing registrations retain
omitted grants during owner updates. Refresh still requires authorization code
under Aegaeon's local policy. Authorization-code registrations require nonempty
redirect URIs and exactly `["code"]` responses. Other grant sets use `[]`
responses and may omit redirects or supply `[]`. Creation derives omitted
responses from the effective grants and returns the substituted set.

Owner PUT preserves omitted/null responses, including an existing empty set.
Changing between code and non-code grants therefore requires an explicit matching
`response_types` value. The returned values are the validated, persisted values.
Management grant updates derive the existing DCR response set in the same
transaction, before success audit/commit, without rotating its registration token
or changing client secrets. Owner PUT retains its existing registration-token
rotation behavior; it is not a credential-preserving repair operation.

Duplicate grants or redirect entries are rejected. Redirect identifiers retain
their accepted bytes, including case, explicit ports and percent escapes. Raw
ASCII whitespace/control characters are rejected before URL parsing; management
no longer skips blanks or serializes parsed redirect URLs. Nonempty redirect
arrays retain existing HTTPS/HTTP-loopback transport rules. Empty logout arrays
retain their separate policy. `none` authentication cannot be paired with
`client_credentials` or authenticated token exchange. Every authentication method
rejects simultaneous non-null `jwks` and `jwks_uri` before key parsing or writes.

The new runtime requires the versioned response and key-source constraints.
It refuses stored grant/response mismatches. This does not provide arbitrary
corrupt-record recovery or change software-statement precedence, full owner
update roundtripping, or postcommit synchronization/token recovery behavior.

## Before upgrading

Stop registration, management, configuration and other database writers. Retain
a restorable private backup, the predecessor executable/schema inventory, and
approved before/after metadata. Use database-administrator authority for offline
repair; do not expose these scripts through an HTTP endpoint. Do not log keys,
registration tokens, client secrets, credential hashes or private input files.

Keep writers stopped continuously through inspection, repair, recheck and migration.
Run both read-only checks against the predecessor database using the candidate
source/toolchain and the existing `AEGAEON_DATABASE_URL` setting:

```sh
nix develop -c cargo run --locked -p aegaeon-server \
  --bin aegaeon-registration-preflight
psql "$AEGAEON_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f scripts/operations/dcr-metadata-preflight.sql
```

Both checks include all retained DCR rows, including deleted clients and old
configuration memberships. They print identifiers, configuration/status and
reason codes only. The strict command uses one `REPEATABLE READ READ ONLY`
transaction and the existing local URI/JWK parsers without fetching remote keys.
It exits 0 after a complete scan with no findings, 2 for blocking findings, and 1
for configuration, backend or output failure. A failed scan is never a clear report.
The SQL report separates `blocks_upgrade=true` findings from representation
corrections. Both strict findings and SQL blocking findings must reach zero. Missing code redirects, refresh without code,
unauthenticated authenticated-only grants, raw whitespace/control in redirects,
malformed key envelopes and missing private-key authentication sources block
upgrade. SQL URI patterns and inline-key checks cover envelope shape only; for example,
a malformed port can pass the SQL URI pattern while failing strict local parsing.
The strict command also checks exact redirect/logout URI arrays, callback URI
relationships and the predecessor/current loader's local JWK parsing, uniqueness
and signature-key selection. Neither check assesses cryptographic key strength.
Strict public-JWK admission/projection is a separate integration dependency.

`derive_response_types` and `clear_unused_remote_key_source` identify the two
explicit migration corrections. They do not grant or remove rights: responses
are derived from the parent grants, and inline-first key selection is preserved
while clearing the unused remote source. The migration does not rewrite inline
key bytes, credentials, grants, scopes, identity, status or membership.

## Select a reachable repair surface

Before installing the new runtime, an active owner with the current registration
access token can use the predecessor registration PUT endpoint to supply approved
redirects or change to supported authenticated client metadata. Its existing
secret generation and registration-token rotation rules still apply. Management
can update reachable clients in the active configuration using its existing role
and version checks. It cannot change a PUBLIC client into a confidential client
or repair JWKS metadata. Management deletion retains the DCR row.

Deleted clients, old configuration memberships and malformed keys that prevent
owner loading cannot be promised HTTP repair. Do not reactivate or delete them
merely to pass the migration. If the intended values or an approved disposition
are unavailable, preserve the row and leave the upgrade blocked.

## Guarded offline repair for retained rows

Use [the SQL template](../../scripts/operations/dcr-metadata-repair.sql) only with
stopped writers, a verified backup and a reviewed private operator change record.
It locks environment, client and registration in that order, requires exactly
one matching input, and compares identity, active and client configuration
membership, status and exact old metadata. A stale/wrong tuple aborts.

The private input is one JSON object with these fields:

| Field | Required value |
| --- | --- |
| `operator_approval_reference` | Nonempty reference to the approved private change record |
| `environment_id`, `client_id` | Exact environment UUID and database client UUID |
| `expected_client_identifier`, `expected_status` | Exact current identifier and retained status |
| `expected_configuration_version_id` | Current client configuration UUID |
| `expected_active_configuration_version_id` | Environment's current active UUID, or null |
| `expected_metadata` | Exact object containing `redirect_uris`, `grant_types`, `client_type`, `auth_method`, `scopes`, `name`, `oauth_profile_id`, `response_types`, `client_id_issued_at`, `post_logout_redirect_uris`, `backchannel_logout_uri`, `backchannel_logout_session_required`, `token_endpoint_auth_signing_alg`, `jwks`, `jwks_uri` |
| `replacement` | Exact object containing `redirect_uris`, `grant_types`, `jwks`, `jwks_uri`, including explicit null key sources |
| `verified_key_backup_reference` | Required when either key source changes; identifies verified intended metadata |

Obtain old metadata privately from the locked target/backup and preserve its
original bytes. Do not include credential hashes in this input. Redirects must
be independently approved valid exact URIs. Grants may only be a nonempty subset
of the existing grants. Removing an unusable authenticated-only grant from a
PUBLIC client is an explicit operator-approved rights change, never an automatic
migration fix. If its rights must be retained and authenticated owner conversion
is unreachable, stop for a separately reviewed administrative repair. No new
grant, generated credential, client-type conversion, purge, resurrection or
implicit key-authority switch is supported. Keys may only be restored from a
trustworthy intended registration/backup; the template's backup reference is an
operator assertion, not automated provenance verification.

Prepare a private `approved-input.sql` (mode 0600), using a private one-line JSON
file with the exact approved object:

```sql
\set ON_ERROR_STOP on
\set ECHO none
CREATE TEMP TABLE dcr_metadata_repair_input (request jsonb);
\copy dcr_metadata_repair_input FROM '/private/approved-registration-repair.jsonl' WITH (FORMAT csv, QUOTE E'\x01', DELIMITER E'\x02')
```

Run both files in the **same connection**:

```sh
psql "$AEGAEON_DATABASE_URL" -X -v ON_ERROR_STOP=1 \
  -f /private/approved-input.sql \
  -f scripts/operations/dcr-metadata-repair.sql
```

The shipped template ends in `ROLLBACK`. Review the private before/after proposal
and successful guarded execution. For an approved repair, create a private exact
copy changing only the final `ROLLBACK` to `COMMIT`, record its digest and approval,
and execute it with the same approved input. A repeated input after a successful
change fails its old-value guard; reconstruct and review any further repair.
The script preserves credentials, status, identity, membership, scopes and audit
rows and does not forge a protocol audit event. Record the administrator's
operation separately. It keeps predecessor response constraints intact; do not
write new-schema-only empty responses before the forward migration.

## Migrate and retry

Rerun both the strict command and SQL all-row report until neither has blocking
findings. Preserve valid legacy response/dual-source correction notices separately. With writers still
stopped, apply `20261002110000_registration_metadata_consistency.sql` through
Atlas's transactional migration inventory (`atlas migrate apply --env local`).
The migration repeats SQL relationship/envelope checks under locks and aborts
atomically if they fail; it does not run the Rust URI/JWK parsers. Direct SQL
execution without the strict preflight is not the complete accepted upgrade
procedure. A previous report is not a transaction-time guarantee. Atlas tracks
successful application once. Do not replay its SQL manually after success.
Retry a failed application only after an approved repair and both fresh checks.
Fresh desired schema and the migration require response sets of `[]` or `[code]`
and mutually exclusive non-null key sources.

Clearing `jwks_uri` changes the runtime client projection fingerprint even when
inline-first key selection stays the same. Operator redirect, grant or key
changes can also invalidate captured authorization contexts. Preserve prior
snapshots/evidence at their original bytes and follow normal runtime reload and
restart procedures; do not preserve stale fingerprints or promise session or
lineage continuity. A postcommit synchronization error does not roll back a
committed owner update or its rotated registration token.
