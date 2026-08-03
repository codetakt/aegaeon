# Runtime Configuration Operations

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This runbook covers runtime configuration authority for `aegaeon-server`.

## Authority mode

PostgreSQL management-database runtime configuration is mandatory. Startup fails closed unless a
database URL is configured, the database is reachable, and an active management
environment/configuration version matches the issuer selected by `AEGAEON_RUNTIME_ISSUER_HOST`.
`AEGAEON_RUNTIME_ISSUER_HOST` is a process-local selector only; the public issuer URL is the
database Environment `issuer_url`.

`AEGAEON_CONFIG_AUTHORITY` was removed. Setting it to any value, including the former
`management-database` or `startup-environment` values, is a configuration error. Protocol-level
tests may still construct in-process stores directly, but the `aegaeon-server` process has no
supported startup-environment authority.

At startup, the server preflights the `aegaeon.dynamic_client_registrations` and
`aegaeon.environment_dcr_bearer_tokens` tables, required columns, uniqueness indexes, and token hash
constraints before hydrating database-backed runtime clients and DCR bearer policy.

In this mode, management API client mutations and public DCR/RFC 7592 mutations commit to
PostgreSQL first, then refresh the issuer-scoped runtime OAuth/PAR client snapshot. DCR management
tokens are stored as SHA-256 hashes in `dynamic_client_registrations`; generated client secrets are
stored as argon2id hashes in `client_secrets` and are disclosed only in the creation response or
when a previously non-secret client is updated to a secret-based authentication method. Optional
`/register` bearer gating is environment-scoped, configured through
`/api/v1/teams/{teamId}/environments/{environmentId}/dcrBearerToken`, and stored only as a SHA-256
hash in `environment_dcr_bearer_tokens`. The management endpoint trims submitted tokens, rejects
empty tokens and values shorter than 32 bytes, and records set/delete audit events in the same
database transaction without storing the raw token or hash in the audit payload.
The old `AEGAEON_DCR_BEARER_TOKEN` startup fallback was removed from the server process. Use the
management DCR bearer-token endpoint so the token hash is scoped to the environment and audited in
PostgreSQL.

Issuer-scoped policy lifetimes are also hydrated from the active management configuration at
startup. This includes access-token TTL, refresh-token TTL, authorization-code/state/nonce TTL, PAR
`request_uri` TTL, local end-user auth-session TTL/capacity, upstream OIDC authorization state TTL,
and upstream logout relay TTL. DPoP nonce enforcement and nonce TTL, private_key_jwt replay windows,
JWT bearer replay windows and `sub == client_id` policy, Request Object `jti` replay windows,
step-up challenge TTL, JWT access-token/JWT introspection response enablement, JWT introspection
response TTL, ACR advertised/default/local-password policy, Rich Authorization Request
`authorization_details` type support, client assertion algorithm allowlists, `kid` requirements,
the issuer crypto profile (`policy.cryptoProfile`), and the runtime signing-key algorithm allowlist
(`policy.allowedSigningAlgorithms`) are served from the same snapshot. OpenID Federation cache
TTLs/capacity and optional outbound domain allowlisting
(`policy.federationOutboundAllowedDomains`) are also served from the active policy snapshot rather
than environment variables. Upstream OIDC provider outbound domain allowlisting
(`policy.upstreamOutboundAllowedDomains`) is a separate active-policy field and applies to
discovery, token, JWKS, and redirect-target HTTP calls. Upstream discovery endpoint admission applies
the same policy to `authorization_endpoint`, `token_endpoint`, `jwks_uri`, and the optional
`end_session_endpoint`: each must be an absolute HTTPS URL with a host, no credentials, no query, and
no fragment. If the allowlist is non-empty, every discovered endpoint host must match it; unsafe
literal non-routable targets are rejected during metadata/redirect admission. Server-performed
outbound discovery, token, JWKS, and upstream refresh HTTP calls additionally use the non-routable
DNS resolver/private-target check and redirect policy. Test builds may use loopback HTTP mock
providers, but production server deployments must not depend on that exception.
Saved upstream logout sessions are not treated as permanent policy admissions: front-channel logout
redirect and relay target construction rechecks the stored `end_session_endpoint` against the current
active `policy.upstreamOutboundAllowedDomains` before appending logout parameters.
Runtime signing keys in `aegaeon.runtime_keys` are validated against
`policy.allowedSigningAlgorithms` at startup and when operators create or activate signing keys
through the management API. Redis connection URLs remain process-global system settings; the TTLs
served by those stores come from the management snapshot.
New issuer-scoped runtime policy knobs must be added to the management database snapshot rather
than to startup environment variables.

The upstream discovery/JWKS metadata body caches are process-local, bounded, and non-authoritative:
they only reduce repeated network fetches. They are not used for single-use protocol state or
cross-node coordination, and they are outside the correctness claim for hosted multi-node runtime
state. Shared protocol state remains PostgreSQL/Redis-backed.

The supported `aegaeon-server` process requires PostgreSQL plus DB/Redis-backed shared runtime
stores at startup. There is no server deployment-mode selector and no supported process-local
runtime-state startup posture. The former integration-fixture cfg/env switch is retired; any
process-local runtime-store constructors that remain are unit-test/proof-harness internals and are
not externally enableable.

Shared runtime-store URLs must use `rediss://` for non-loopback endpoints. Plain `redis://` is
accepted only for loopback development endpoints such as `localhost`, `127.0.0.1`, or `[::1]`.
Query and fragment components are rejected so atomic-store topology checks cannot ignore
connection-affecting URL options.
The source-managed preflight inventory currently covers these always-required stores:

| Runtime surface | Shared-store env |
| --- | --- |
| PAR `request_uri` store | `AEGAEON_PAR_REDIS_URL` |
| Authorization-code/state/nonce store | `AEGAEON_AUTH_CODE_REDIS_URL` |
| Token/revocation store | `AEGAEON_TOKEN_STORE_REDIS_URL` |
| DPoP replay store | `AEGAEON_DPOP_REDIS_URL` |
| JWKS runtime state | `AEGAEON_JWKS_REDIS_URL` |
| Request Object `jti` replay store | `AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL` |
| Browser auth-session store | `AEGAEON_AUTH_SESSION_REDIS_URL` |
| Device-code store | `AEGAEON_DEVICE_CODE_REDIS_URL` |
| Device CSRF store | `AEGAEON_DEVICE_CSRF_REDIS_URL` |
| Device verification rate limiter | `AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL` |
| Local auth CSRF store | `AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL` |
| Local login rate limiter | `AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL` |
| Step-up challenge store | `AEGAEON_STEPUP_REDIS_URL` |
| Management session store | `AEGAEON_MANAGEMENT_SESSION_REDIS_URL` |
| Management login rate limiter | `AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL` |
| Upstream auth state store | `AEGAEON_UPSTREAM_AUTH_REDIS_URL` |
| Upstream logout relay store | `AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL` |

Feature-gated shared stores are required when the corresponding runtime surface is enabled:

| Runtime surface | Shared-store env |
| --- | --- |
| DPoP nonce store | `AEGAEON_DPOP_NONCE_REDIS_URL` |
| Client assertion replay store | `AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL` |
| OIDC logout/session store | `AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL` |

The implementation and test inventory for this boundary is source-managed in:

- `crates/server/src/config/runtime_boundary/shared_store.rs`
- `crates/server/src/config/tests/runtime_boundaries/inventory.rs`
- `crates/server/src/config/tests/runtime_boundaries/deployment_preflight.rs`
- `crates/server/src/config/tests/runtime_boundaries/shared_store_requirements.rs`
- `crates/server/tests/server_process_env_test.rs`

Run the focused regression lane with:

```bash
nix develop .#default --command bash -c \
  'cargo test -p aegaeon-server --lib config::tests -- --test-threads=1'
nix develop .#default --command bash -c \
  'cargo test -p aegaeon-server --test server_process_env_test -- --test-threads=1'
```

The active configuration also carries a `keyStore` public configuration for the management API's
local database key-material intake policy. In the current management surface, only `databaseEncrypted` public
metadata is admitted and secret material is rejected from that document. Operational key material is
loaded from `aegaeon.runtime_keys` for the active issuer/configuration version, and each runtime key
records its own provider (`databaseEncrypted` or `awsKms`).

OIDC requires an ACTIVE `OIDC_ID_TOKEN_SIGNING` runtime key when `policy.oidcEnabled=true`; JWT
access-token signing and JWT introspection signing likewise require an ACTIVE runtime key when their
corresponding policy flags are enabled. Public Federation OP signing is not part of the supported
runtime and has no production runtime-key usage. Activation rejects a candidate configuration before
switching it active if any required runtime key is absent. RETIRING OIDC signing keys are published
for JWKS overlap. If an ACTIVE `OIDC_REQUEST_OBJECT_DECRYPTION` key is present, encrypted Request
Object decryption is enabled.

Operators create local database-backed shared keys through the management API `runtimeKeys`
endpoint. Provider `databaseEncrypted` accepts unencrypted PKCS#8 private key PEM at creation time,
stores only an encrypted key handle plus derived public JWK, and never returns or audits the private
key material. When the server is built with the `kms-aws` feature, the same management API also
accepts provider `awsKms` for `OIDC_ID_TOKEN_SIGNING` runtime keys only; it derives and stores the
public JWK plus encrypted KMS key handle, while the stored provider configuration contains only the
AWS region. Hosted bootstrap uses the same narrowed `awsKms` runtime-key boundary.

`CreateRuntimeKeyRequest.activate=true` atomically retires the existing ACTIVE key for the same
usage before inserting the replacement as ACTIVE; without activation, the key is stored as NEXT.
Operators can later call `runtimeKeys/activateNext` with the intended usage to promote that NEXT key
and retire the previous ACTIVE key, or revoke an individual runtime key with
`runtimeKeys/{runtimeKeyId}/revoke`.

Control-plane management policy is not issuer-scoped. The management API reads management-session
TTL/capacity, browser Origin allowlist, and issuer base-domain defaults from
`aegaeon.control_plane_policies`. The corresponding `AEGAEON_MANAGEMENT_*` policy variables are
rejected by the server process so stale env does not shadow or silently diverge from the database
policy row. Management session Redis connectivity remains process-global system configuration.

Team-scoped management API keys are database-backed service principals, not startup secrets. Creating
an API key inserts an `aegaeon.administrators(kind='SERVICE')` principal, a team membership, and an
`aegaeon.api_keys` row in the same PostgreSQL transaction. Automation authenticates with
`Authorization: Bearer <api-key>` and must not send management cookies; browser cookie sessions
continue to use Origin and CSRF checks. Revoking an API key revokes the row, disables the service
principal, and removes its team membership so subsequent requests fail closed through the same RBAC
path as human administrators.

## Management-database drift handling

The server does not live-patch `ServerConfig`, OIDC runtime state, signing material, DCR bearer
policy, or metadata in place. Instead, it monitors the active configuration version, the
active/retiring runtime-key set, the environment DCR bearer token fingerprint, and the active runtime
client projection for the issuer that was hydrated at startup. Policy changes, runtime-key
activation/revocation, and DCR bearer-token changes are fail-closed restart events; they are not
applied as in-process patches.

When the active configuration version changes, when `runtimeKeys/activateNext` or runtime-key
revocation changes the ACTIVE/RETIRING key set, when the DCR bearer token hash changes, or when the
monitor cannot query the management database, the process logs an error under
`runtime_config_monitor`, records a typed runtime restart request, fails readiness, closes new
request admission, and exits with status `78` after graceful shutdown. Same-node management mutations
for the current issuer request the same graceful shutdown path after returning the committed response,
so the supervisor can restart the process with the new snapshot. This prevents a node from serving
stale security policy, stale registration access policy, or stale signing/decryption material after an
operator changes management-database runtime state. Creating a NEXT key alone does not change the
served key set and does not require a restart. Run production deployments under a supervisor that
restarts the process and re-runs readiness checks.

Runtime client projection changes are handled without a restart when possible, with bounded eventual
consistency across nodes. Same-node management API and public DCR/RFC 7592 mutations refresh the
local issuer-scoped OAuth/PAR client snapshot immediately after the PostgreSQL transaction commits.
If that post-commit refresh fails, the server records a typed runtime restart request, readiness fails,
new request admission is closed, and the process exits `78` after graceful shutdown. Other nodes
observe the committed database state through PostgreSQL runtime-authority notifications or the polling
runtime monitor. The monitor compares a database-derived fingerprint with the local runtime client
snapshot; if they differ, it reloads the issuer-scoped OAuth/PAR client snapshot from PostgreSQL. If
that reload fails, the process exits `78` rather than serving stale client registration or credential
state. There is no claim of immediate cross-node client consistency before notification delivery or
the polling monitor runs.

Tune the polling interval through the active database policy:
`policy.runtimeConfigMonitorIntervalSeconds` (`1..=3600`, default `30`). The former
`AEGAEON_RUNTIME_CONFIG_MONITOR_INTERVAL_SECS`, `AEGAEON_RUNTIME_CLIENT_SYNC_INTERVAL_SECS`, and
database `runtimeClientSyncIntervalSeconds` controls were removed and are rejected when present.

Tune JOSE protected-header admission through `policy.joseHeaderMaxLen` (`1..=65536`, default
`4096`). The former `AEGAEON_JOSE_HEADER_MAXLEN` startup fallback was removed and is rejected when
present; update the active configuration document or policy patch instead.

## Operator checklist

- Set the server PostgreSQL URL with `AEGAEON_DATABASE_URL`. `DATABASE_URL` is not a server
  runtime fallback. `AEGAEON_DB_ENABLED` is a removed database-mode toggle; omit it. Any value is
  rejected.
- Set `AEGAEON_RUNTIME_ISSUER_HOST` to the canonical active Environment issuer host. Do not set
  `BASE_URL`; it was removed as a startup public-issuer fallback and is rejected.
- Do not set `AEGAEON_CONFIG_AUTHORITY`; the configuration authority selector was removed.
- Configure the shared Redis store URLs listed above for every enabled runtime surface. Do not rely
  on `AEGAEON_ALLOW_UNSHARED_RUNTIME_STATE` or `AEGAEON_ALLOW_EPHEMERAL_RUNTIME_STATE` for
  `aegaeon-server` startup; those acknowledgements were removed from server startup.
- Configure `policy.upstreamOutboundAllowedDomains` for hosted upstream OIDC providers. Include the
  provider hosts used by discovery, authorization, token, JWKS, and optional end-session metadata.
  Do not publish an upstream `end_session_endpoint` with preexisting query or fragment parameters;
  Aegaeon appends its own logout relay parameters only after endpoint admission and revalidates
  stored logout endpoints against the current active allowlist during logout.
- Ensure the selected issuer host resolves to exactly one active management environment and active
  configuration version.
- Configure the process supervisor to restart on exit status `78`.
- Apply `db/migrations/20260602090000_dynamic_client_registrations.sql` before starting or
  upgrading the server; startup fails closed if the DCR table, required columns, uniqueness
  indexes, or token-hash CHECK constraints are missing.
- Apply `db/migrations/20260606100000_environment_dcr_bearer_tokens.sql` before starting or
  upgrading the server; startup fails closed if the DCR bearer token hash table or CHECK constraints
  are missing.
- Apply `db/migrations/20260625100000_management_policy_crypto_profile.sql` before starting or
  upgrading the server; older active policy snapshots are backfilled to `policy.cryptoProfile =
  "compat"` and the environment-policy projection receives the same value.
- Apply `db/migrations/20260605100000_control_plane_policy.sql` before starting or upgrading the
  server; startup fails closed if the default control-plane policy row is missing.
- Apply `db/migrations/20260630130000_management_api_keys.sql` before starting or upgrading the
  server if management API key automation is used; API keys require the service-principal columns,
  role binding, and `aegaeon.api_keys` table created by this migration.
- Apply `db/migrations/20260605110000_stepup_policy.sql` before starting or upgrading the server;
  older active policy snapshots are backfilled to the default step-up challenge TTL.
- Apply `db/migrations/20260605120000_upstream_runtime_policy.sql` before starting or upgrading
  the server; older active policy snapshots are backfilled to the default upstream authorization and
  logout relay TTLs.
- Apply `db/migrations/20260605130000_jwt_response_policy.sql` before starting or upgrading the
  server; older active policy snapshots are backfilled to disabled JWT access-token/JWT
  introspection response posture and the default introspection response TTL.
- Apply `db/migrations/20260605140000_acr_authorization_details_policy.sql` before starting or
  upgrading the server; older active policy snapshots are backfilled to empty ACR and
  `authorization_details` supported-type allowlists with unset default/local-password ACRs.
- Apply `db/migrations/20260605150000_runtime_keys.sql` before starting or upgrading the server;
  OIDC startup fails closed when `policy.oidcEnabled=true` and no ACTIVE
  `OIDC_ID_TOKEN_SIGNING` runtime key is present for the active issuer/configuration version.
- Before activating OIDC, create an ACTIVE `OIDC_ID_TOKEN_SIGNING` runtime key through
  `POST /api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys` or hosted bootstrap.
  Use `OIDC_REQUEST_OBJECT_DECRYPTION` only when encrypted Request Objects should be accepted.
- Set `AEGAEON_JWKS_REDIS_URL`. Redis is the shared runtime-state authority for circuit phase,
  half-open probe coordination, and `kid` fingerprint history. JWKS body caching is bounded,
  process-local, and non-authoritative.
- Stage key rotation by creating a NEXT runtime key for the same usage, then call
  `POST /api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys/activateNext` with that
  usage. Expect the runtime configuration monitor to restart nodes after activation.
- Treat repeated `runtime_config_monitor` exits as a release/configuration incident until the active
  configuration row and database connectivity are verified.
- Keep `/health` and load-balancer readiness checks tied to the restarted process, not to stale
  instances that are already exiting.

## Expected logs

At startup, a healthy management-database process logs that runtime configuration was hydrated from
the management database, including `issuer_host` and `configuration_version_id`.

During steady state, debug logs under `runtime_config_monitor` report that the version is unchanged.
On drift or monitor failure, an error log includes the loaded version, current active version when
available, and the issuer host before the process requests graceful restart and exits.
