# Server Environment: Federation, Observability, And Test Settings

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This document is part of the split server environment-variable reference. Use this file for the detailed section below.

## OpenID Federation (RP / trust-chain runtime)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_FEDERATION_OP_ENABLED` | _removed_ | `environment` | Removed startup-environment fallback. Public OpenID Federation OP publication is not part of the supported server runtime. |
| `AEGAEON_FEDERATION_ENTITY_EXP_SECS` | _removed_ | `environment` | Removed startup-environment fallback. The corresponding `policy.federationEntityExpSeconds` document field is retired and rejected. |
| `AEGAEON_FEDERATION_AUTHORITY_HINTS` | _removed_ | `environment` | Removed startup-environment fallback. The corresponding `policy.federationAuthorityHints` document field is retired and rejected. |
| `AEGAEON_FEDERATION_OUTBOUND_ALLOWED_DOMAINS` | _not supported_ | `environment` | OpenID Federation outbound domain allowlisting is intentionally database-managed as `policy.federationOutboundAllowedDomains`; no environment-variable fallback exists. |
| `AEGAEON_FEDERATION_ENTITY_CACHE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.federationEntityCacheTtlSeconds` is authoritative. |
| `AEGAEON_FEDERATION_CHAIN_CACHE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.federationTrustChainCacheTtlSeconds` is authoritative. |
| `AEGAEON_FEDERATION_CACHE_MAX_ENTRIES` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.federationCacheMaxEntries` is authoritative. |
| `AEGAEON_FEDERATION_LIST_RATE_LIMIT_REDIS_URL` | _removed_ | `system` | Removed with the public OpenID Federation OP list endpoint. Startup fails closed if this variable is present. |

The supported runtime uses OpenID Federation for outbound entity-statement fetch, trust-chain
validation, upstream federation metadata admission, and persistent federation cache management.
Public OP Entity Configuration, fetch, list, and resolve publication endpoints are not routed in
production. Future OP publication work must reintroduce a database-managed signing boundary before
any public endpoint or compliance claim is activated.

## Upstream OIDC connections (federated logins)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_UPSTREAM_AUTH_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback TTL (seconds, valid range 1-3600) for upstream OIDC authorization request state. In the supported PostgreSQL-backed runtime, `policy.upstreamAuthTtlSeconds` is authoritative. |
| `AEGAEON_UPSTREAM_AUTH_REDIS_URL` | _unset_ | `system` | Redis URL for shared upstream OIDC authorization request state. Required by the supported server runtime; client secrets are reloaded from the database on callback and are not stored in this Redis state. |
| `AEGAEON_UPSTREAM_OUTBOUND_ALLOWED_DOMAINS` | _not supported_ | `environment` | Upstream OIDC discovery, token, JWKS, and redirect-target outbound domain allowlisting is intentionally database-managed as `policy.upstreamOutboundAllowedDomains`; no environment-variable fallback exists. |
| `AEGAEON_UPSTREAM_DISCOVERY_CACHE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.upstreamDiscoveryCacheTtlSeconds` is authoritative. |
| `AEGAEON_UPSTREAM_JWKS_CACHE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.upstreamJwksCacheTtlSeconds` is authoritative. |
| `AEGAEON_UPSTREAM_LOGOUT_RELAY_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback TTL (seconds, valid range 1-86400) for upstream logout relay state. In the supported PostgreSQL-backed runtime, `policy.upstreamLogoutRelayTtlSeconds` is authoritative. |
| `AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL` | _unset_ | `system` | Redis URL for shared upstream logout relay state. Required by the supported server runtime so upstream logout callbacks can land on any node. |

## Discovery metadata (mTLS aliases)

When `policy.mtlsEnabled=true`, RFC 8705 fields are exposed in discovery metadata:
`tls_client_certificate_bound_access_tokens` and `mtls_endpoint_aliases`.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_MTLS_ENABLED` | _removed_ | `environment` | Removed startup-environment fallback. Enables mTLS metadata fields in discovery documents. In the supported PostgreSQL-backed runtime, `policy.mtlsEnabled` is authoritative. |
| `AEGAEON_MTLS_BASE_URL` | _removed_ | `environment` | Removed startup-environment fallback base URL used for the mTLS endpoint aliases. In the supported PostgreSQL-backed runtime, `policy.mtlsBaseUrl` is authoritative. |
| `AEGAEON_MTLS_ALIAS_PAR` | _removed_ | `environment` | Removed startup-environment fallback extension: also publish the PAR endpoint under `mtls_endpoint_aliases`. In the supported PostgreSQL-backed runtime, `policy.mtlsAliasParEnabled` is authoritative. |

## Observability

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_OBSERVABILITY_API_KEY` | _unset_ | `development/test` | Required by `aegaeon-observability-seed` to create the managed API key used for authenticated metrics checks. It is not read by the server process. |
| `AEGAEON_EXPOSE_METRICS_ON_MAIN` | _removed_ | `system` | Removed. Metrics are available only through the authenticated management endpoint `/api/v1/operations/metrics`. |

## JOSE policy knobs

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_JOSE_HEADER_MAXLEN` | _removed_ | `environment` | Removed startup-environment fallback. In the supported PostgreSQL-backed runtime, `policy.joseHeaderMaxLen` is authoritative for the maximum length (characters) of Base64URL-encoded protected JOSE headers. |

The raw JSON backend is fixed by the server release claim boundary. Runtime backend override
environment variables are removed for `aegaeon-server`; setting any variable with the
`AEGAEON_RAW_JSON_BACKEND` prefix fails closed at startup. The JOSE crate may still exercise
backend-selection tests directly, but deployed server instances must not downgrade promoted
surfaces to compatibility parsing.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_RAW_JSON_BACKEND` | _removed_ | `system` | Removed global raw JSON backend override. Server startup fails closed if present. |
| `AEGAEON_RAW_JSON_BACKEND_` | _removed prefix_ | `system` | Removed raw JSON backend override prefix. Any environment key beginning with this prefix fails closed at server startup. |
| `AEGAEON_RAW_JSON_BACKEND_GENERIC_OBJECT` | _removed_ | `system` | Removed legacy generic-object raw JSON backend override for server startup. |
| `AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER` | _removed_ | `system` | Removed per-surface backend override for JOSE protected headers. |
| `AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT` | _removed_ | `system` | Removed per-surface backend override for Request Object payload admission. |
| `AEGAEON_RAW_JSON_BACKEND_CLIENT_REGISTRATION` | _removed_ | `system` | Removed per-surface backend override for DCR client-registration metadata admission. |
| `AEGAEON_RAW_JSON_BACKEND_SOFTWARE_STATEMENT` | _removed_ | `system` | Removed per-surface backend override for software-statement payload admission. |
| `AEGAEON_RAW_JSON_BACKEND_PRIVATE_KEY_JWT_PAYLOAD` | _removed_ | `system` | Removed per-surface backend override for `private_key_jwt` payload admission. |
| `AEGAEON_RAW_JSON_BACKEND_JWT_BEARER_ASSERTION_PAYLOAD` | _removed_ | `system` | Removed per-surface backend override for JWT bearer assertion payload admission. |
| `AEGAEON_RAW_JSON_BACKEND_OIDC_ID_TOKEN_PAYLOAD` | _removed_ | `system` | Removed per-surface backend override for OIDC ID Token payload admission. |
| `AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_HEADER` | _removed_ | `system` | Removed per-surface backend override for JWT access-token header admission. |
| `AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_PAYLOAD` | _removed_ | `system` | Removed per-surface backend override for JWT access-token payload admission. |
| `AEGAEON_RAW_JSON_BACKEND_FEDERATION_ENTITY_STATEMENT` | _removed_ | `system` | Removed per-surface backend override for OpenID Federation Entity Statement admission. |
| `AEGAEON_RAW_JSON_BACKEND_FEDERATION_TRUST_MARK` | _removed_ | `system` | Removed per-surface backend override for OpenID Federation Trust Mark admission. |

## Test-only configuration

These knobs exist to support local testing and conformance harnesses. Avoid using them in
production deployments.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ENABLE_TEST_CLIENTS` | `0` | `test` | Seeds built-in in-memory clients. This is for tests/conformance only, logs a warning when enabled, and is rejected by release builds. |
| `AEGAEON_TEST_ALLOW_NET` | `0` | `test` | If enabled, allows tests that make outbound HTTP calls (default is fail-closed). |
| `AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS` | `0` | `test` | Allows HTTP loopback `jwks_uri` values in debug builds for local tests. Keep disabled in production. |
| `AEGAEON_BACKCHANNEL_LOGOUT_ALLOW_HTTP_LOOPBACK_FOR_TESTS` | `0` | `test` | Allows HTTP loopback Back-Channel Logout URIs in debug builds for local tests. Keep disabled in production. |
| `AEGAEON_TEST_RSA_FIXTURES` | `0` | `test` | Enables RSA fixtures for JWKS/JWT tests. |
| `AEGAEON_TEST_CLIENT_REDIRECT_URIS` | `https://example.com/callback` | `test` | Seeds the in-memory test clients’ redirect URIs (whitespace/comma-separated). |
| `AEGAEON_TEST_CLIENT_JAR_PEM` | _unset_ | `test` | PEM used to validate Request Objects for the default `test-client` (conformance). |
| `AEGAEON_TEST_CLIENT_BACKCHANNEL_LOGOUT_URI` | _unset_ | `test` | If set, configures `backchannel_logout_uri` for the default `test-client` (OIDC logout conformance). |
| `AEGAEON_TEST_CLIENT_BACKCHANNEL_LOGOUT_SESSION_REQUIRED` | `0` | `test` | If enabled, sets `backchannel_logout_session_required=true` for the default `test-client`. |
| `AEGAEON_TEST_CLIENT2_BACKCHANNEL_LOGOUT_URI` | _unset_ | `test` | If set, configures `backchannel_logout_uri` for the default `test-client2`. |
| `AEGAEON_TEST_CLIENT2_BACKCHANNEL_LOGOUT_SESSION_REQUIRED` | `0` | `test` | If enabled, sets `backchannel_logout_session_required=true` for the default `test-client2`. |
| `AEGAEON_TEST_JWT_BEARER_GRANT_PUB_PEM` | _unset_ | `test` | PEM public key used to validate JWT bearer grant assertions in tests. |
| `AEGAEON_TEST_ENABLE_JWT_BEARER_GRANT_CLIENT` | `0` | `test` | If enabled, registers a test client for JWT bearer grant flows. |
| `AEGAEON_TEST_ENABLE_TOKEN_EXCHANGE_CLIENT` | `0` | `test` | If enabled, registers a test client for token exchange flows. |
| `AEGAEON_TEST_ENABLE_DEVICE_CODE_CLIENT` | `0` | `test` | If enabled, registers a test client for device-code client fixtures. |
| `AEGAEON_TEST_REDIS_URL` | _unset_ | `test` | Redis URL used by ignored Redis-backed integration tests across replay stores, PAR, auth/session, device, step-up, management, and JWKS runtime-state paths. Use `rediss://` for non-loopback endpoints; plain `redis://` is accepted only for loopback development endpoints. |
| `AEGAEON_TEST_LOCAL_LOGIN_CSRF_REDIS_URL` | _unset_ | `test` | Redis URL used by local-login CSRF store tests. |
| `AEGAEON_TEST_LOCAL_RECOVERY_CSRF_REDIS_URL` | _unset_ | `test` | Redis URL used by local-recovery CSRF store tests. |
| `AEGAEON_RSA_JWK_KID` | `test-kid-rsa` | `test` | RSA JWK `kid` for test fixtures. |
| `AEGAEON_RSA_JWK_N` | _unset_ | `test` | RSA JWK modulus (`n`) for JWKS/JWT tests (required when RSA fixtures are used). |
| `AEGAEON_RSA_JWK_E` | `AQAB` | `test` | RSA JWK exponent (`e`) for JWKS/JWT tests. |
| `AEGAEON_RSA_PRIV_PEM` | _unset_ | `test` | RSA private key PEM used by JWT/JWKS E2E tests. |
| `AEGAEON_RSA_PUB_PEM` | _unset_ | `test` | RSA public key PEM used by JWT/JWKS E2E tests. |
| `AEGAEON_E2E_JWKS_DUMP` | _unset_ | `test` | If set, dumps JWKS responses for E2E diagnostics. |
| `AEGAEON_E2E_JWT_DUMP` | _unset_ | `test` | If set, dumps JWT bodies for E2E diagnostics. |
| `AEGAEON_E2E_JWT_HEADER_DUMP` | _unset_ | `test` | If set, dumps JWT headers for E2E diagnostics. |
| `AEGAEON_E2E_JWT_CLAIMS_DUMP` | _unset_ | `test` | If set, dumps JWT claims for E2E diagnostics. |
| `AEGAEON_E2E_METRICS_DUMP` | _unset_ | `test` | If set, dumps metrics output during E2E tests. |

## Load testing

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEG_LOADTEST_CLIENT_ID` | `test-client` | `test` | Client ID used by load test scenarios. |
| `AEG_LOADTEST_CLIENT_SECRET` | _unset_ | `test` | Client secret used by load test scenarios. |
| `AEG_LOADTEST_CLIENT_SECRET_POST` | _unset_ | `test` | Client secret (client_secret_post) used by load test scenarios. |
| `AEG_LOADTEST_REDIRECT_URI` | _unset_ | `test` | Redirect URI used by load test scenarios. |
| `AEG_LOADTEST_SCOPE` | `read write` | `test` | Scope string used by load test scenarios. |
| `AEG_LOADTEST_OIDC_SCOPE` | `openid profile` | `test` | Scope string used when the load scenario must acquire an OIDC `userinfo` token. |
| `AEG_LOADTEST_PROOF_ORIGIN` | _unset_ | `test` | Public origin used when constructing `DPoP` proof `htu` values; set this when the server validates against an HTTPS origin that differs from the local HTTP target URL. |
| `AEG_LOADTEST_PUBLIC_ORIGIN` | _unset_ | `test` | Backward-compatible alias for `AEG_LOADTEST_PROOF_ORIGIN`. Prefer the proof-specific name for new setups. |

## Source references

- Server config parsing: `crates/server/src/config.rs`
- Transport enforcement: `crates/server/src/middleware/tls.rs`
- OIDC config parsing: `crates/server/src/oidc/config.rs`
- DCR policy gates + SSA validation: `crates/server/src/dcr.rs`
- DCR persistence + bearer-token hash storage: `crates/server/src/dcr_persistence.rs`
- Runtime client snapshot synchronization: `crates/server/src/runtime_clients.rs`
- JWKS fetcher + caching: `crates/server/src/client_registry.rs`
- Request Object self-check: `crates/server/src/request_object.rs`
