# Server Environment: Core System Settings

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This document is part of the split server environment-variable reference. Use this file for the detailed section below.

## Conventions

- **Booleans**: set to `1` to enable and `0` to disable. Many call sites also accept
  `true`/`yes` (case-insensitive), but `1` is the most portable choice.
- **Durations**: seconds unless explicitly noted otherwise.
- **Lists**: comma-separated (whitespace is trimmed).

## Reload semantics

- Startup environment variables are reserved for bootstrap/system boundaries such as database,
  Redis, host-local trust, proxy trust, and diagnostics.
- Issuer-scoped runtime policy and control-plane policy are loaded from PostgreSQL. Protected
  runtime request admission revalidates the active runtime-authority revision before serving
  requests, and management client projections can synchronize from the database while the process
  is running.
- Policy, runtime-key, and DCR token-source changes that alter the active issuer snapshot request
  graceful restart instead of relying on process-local environment fallbacks. The JWKS fetcher keeps
  bounded process-local body cache only; its authoritative policy and shared circuit state remain
  PostgreSQL/Redis-backed.

For operational simplicity, treat runtime policy changes as PostgreSQL management-plane changes and
system environment changes as requiring a restart unless a setting is explicitly marked as dynamic
below.

## Configuration scopes (management plane)

Aegaeon uses two distinct configuration scopes:

- `system`: process-global operator configuration (database connectivity, proxy trust, JWKS fetcher
  tuning, etc.). These remain environment variables and are not tenant-admin configurable.
- `control-plane`: management API policy that is global to the control plane. In the supported
  server runtime, these values live in database-backed control-plane policy.
- `environment`: issuer-scoped data plane configuration. In the management plane design, these
  values live in the Environment configuration snapshot (`configuration_versions.configurationDocument`)
  and are edited via the management API.

The `aegaeon-server` binary uses PostgreSQL as the runtime configuration authority. The process
hydrates the issuer-scoped active Environment configuration from PostgreSQL at startup, synchronizes
active management-plane clients from that issuer, and monitors the active configuration version. If
the active version changes or the monitor cannot query it, the process records a typed runtime restart
request, fails readiness, closes new request admission, and exits with code `78` after graceful
shutdown so a supervisor can restart it with a fresh snapshot. The former
`AEGAEON_CONFIG_AUTHORITY` selector was removed; setting it to any value fails closed.
Policy-mutation responses report this explicitly via `runtimeActivation`.

The tables below include a `Scope` column to document authority boundaries. New issuer-scoped knobs
must be database-backed Environment configuration unless they are truly process-global system
settings. Startup-environment runtime-policy knobs are listed only as removed negative
configuration; they must not be used for the supported server path.

For the target scope redesign and migration plan, see
`docs/architecture/configuration-scope-plan.md`.

## Core identity & logging

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_RUNTIME_ISSUER_HOST` | _unset_ | `system` | Required runtime selector for `aegaeon-server`. The value is a canonical issuer host (`host` or `host:port`, no scheme/path/query/fragment/userinfo) and must match exactly one ACTIVE management Environment `issuer_host`. The public issuer URL is loaded from the database Environment (`issuer_url`), not from process environment. |
| `BASE_URL` | _removed_ | `environment` | Removed startup-environment public issuer fallback. Setting it for `aegaeon-server` fails closed; manage Environment issuer host/URL in PostgreSQL and set `AEGAEON_RUNTIME_ISSUER_HOST` only as the process-local selector. |
| `RUST_LOG` | `info` | `system` | Standard `tracing_subscriber` filter (e.g., `info,aegaeon_server=debug`). |
| `GIT_COMMIT` | _unset_ | `system` | Optional commit SHA captured at build time via `option_env!` for status/diagnostics. Not read at runtime. |

The server bind address is configured via CLI flags:

```bash
./aegaeon-server --host 127.0.0.1 --port 8080
```

## Database (PostgreSQL / SQLx)

PostgreSQL is required. Startup fails if the database URL is missing, the database cannot be
reached, or the runtime client/DCR schema contract is missing. Apply the Atlas/schema migration set,
including `db/migrations/20260602090000_dynamic_client_registrations.sql`, before running the
server.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_DATABASE_URL` | _unset_ | `system` | Required Postgres connection string for the server runtime. |
| `AEGAEON_DB_MAX_CONNECTIONS` | `10` | `system` | SQLx pool size cap. |
| `AEGAEON_DB_ACQUIRE_TIMEOUT_SECS` | `5` | `system` | Timeout (seconds) when acquiring a pooled connection. |

`AEGAEON_DB_ENABLED` was removed. PostgreSQL is mandatory, and startup rejects this variable even
when it is set to a truthy value.

## Runtime state and configuration authority

These guardrails prevent accidental runtime postures that would silently weaken single-use,
revocation, or policy-activation semantics.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_DEPLOYMENT_MODE` | _removed_ | `system` | Removed deployment-mode selector. Startup fails closed if this variable is present; all supported deployments require PostgreSQL plus DB/Redis-backed shared runtime state. |
| `AEGAEON_ALLOW_UNSHARED_RUNTIME_STATE` | _removed_ | `system` | Removed legacy acknowledgement flag. Startup fails closed if this variable is present; configure DB/Redis-backed shared stores for competing runtime state instead. |
| `AEGAEON_ALLOW_EPHEMERAL_RUNTIME_STATE` | _removed_ | `system` | Removed non-production escape hatch for process-local protocol stores. Startup fails closed if this variable is present. |
| `AEGAEON_CONFIG_AUTHORITY` | _removed_ | `system` | Removed runtime authority selector. The server always hydrates runtime configuration from PostgreSQL-backed management state; startup fails closed if this variable is present. |
| `AEGAEON_RUNTIME_CONFIG_MONITOR_INTERVAL_SECS` | _removed_ | `system` | Removed environment override. Configure `policy.runtimeConfigMonitorIntervalSeconds` through the management API/database policy. |
| `AEGAEON_RUNTIME_CLIENT_SYNC_INTERVAL_SECS` | _removed_ | `system` | Removed legacy environment override. Runtime client projection convergence is handled by PostgreSQL notifications plus `policy.runtimeConfigMonitorIntervalSeconds`; the separate runtime-client sync interval was retired. |
| `AEGAEON_RATE_LIMIT_REDIS_URL` | _removed_ | `system` | Removed shared Redis fallback for rate limiters. Configure each rate-limit surface Redis URL explicitly; startup fails closed if this variable is present. |

The shared-store preflight currently requires shared stores for PAR `request_uri`,
authorization code/state/nonce, token/revocation, Request Object `jti`, browser auth sessions,
local auth CSRF, local login rate limiting, step-up challenges, management sessions, management
login rate limiting, device-code state, device CSRF, device verification rate limiting,
and JWKS runtime state. With the default DPoP posture, it also requires shared DPoP replay and
nonce storage. OIDC logout/session storage is required when OIDC is enabled. Upstream auth and
upstream logout relay stores are always required because PostgreSQL-backed upstream account/link
state is part of the supported server runtime.
`AEGAEON_JWKS_REDIS_URL` coordinates JWKS circuit breaker state, half-open probes, and `kid`
fingerprint history across nodes.
The legacy on-disk JWKS body cache is removed; multi-node JWKS coordination must use Redis-backed
runtime state.

Authorization-code exchange consumes the code and commits the issued access/refresh grant with one
Redis Lua script. `AEGAEON_AUTH_CODE_REDIS_URL` and `AEGAEON_TOKEN_STORE_REDIS_URL` must reference
the same Redis endpoint; startup fails closed when both are configured with different values.
Runtime Redis keys use an environment-level hash tag so this multi-key commit remains single-slot
under Redis Cluster.

The server no longer has a deployment-mode distinction for runtime-state safety: supported
deployments must configure the same shared-store inventory and must not silently use process-local
single-use, replay, revocation, CSRF, session, or rate-limit state.
Shared runtime Redis URLs must use `rediss://` for non-loopback endpoints; plain `redis://` is
accepted only for local loopback development endpoints. Redis URLs must not include query or
fragment components; encode connection policy in the managed Redis endpoint configuration rather
than in per-surface URL options.

The key-material preflight separately rejects process-local signing keys for JWT access
tokens, JWT introspection responses, OIDC ID Tokens, and OIDC Request Object decryption keys.
Use management-database runtime keys before enabling those surfaces.
For OIDC ID Token signing, a runtime key can use provider `databaseEncrypted` or the hosted-bootstrap
`awsKms` path when that feature is enabled and classified.
