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

### Refresh grant continuity and upgrade

Upstream refresh tokens are stored in a version 3 encrypted envelope together
with the original validated ID Token's issuer, subject, audience members,
optional authentication time and nonce, and the original upstream client ID.
The existing environment, issuer, subject digest, connection and generation
bindings remain authenticated. Original claims are not new plaintext columns.
A callback only replaces this context when it receives a new refresh token.
Rotations retain the original context; a callback without a refresh token does
not attach a new authentication to an older grant.

A refreshed ID Token is optional. If present, it must pass existing validation
and match the original issuer, subject and audience set. String and singleton
array audiences are equivalent; order and duplicates do not change that set.
A supplied `auth_time` or nonce must equal the corresponding captured original
value. If the original value was absent, a newly supplied value is refused;
reauthenticate instead. Omission on refresh is allowed. These continuity rules
follow OpenID Connect Core 1.0 errata set 2 §12.2, with the stated fail-closed
policy for an uncorroborated authentication time. They do not adopt additional
`azp` extension semantics. Changing the active connection's client ID requires
new authentication. Rejected responses expose no new upstream tokens and do
not replace stored token/context state. Generation comparisons prevent a stale
response from overwriting a later callback or rotation.

Version 2 envelopes lack original context. They are refused before upstream
exchange with `400 invalid_grant` and a generic reauthentication-required
message. A fresh successful callback receiving a refresh token writes version 3;
no SQL migration or bulk token rewrite is performed. Coordinate all readers and
writers during rollout: older binaries cannot read version 3, and rollback may
require reauthentication. Preserve the prior database/token backups under the
existing secret controls. Estimate affected older links without exposing token
bytes using this read-only query:

```sql
SELECT count(*) AS legacy_upstream_refresh_links
FROM aegaeon.account_links
WHERE substring(upstream_refresh_token_encrypted
                FROM 1 FOR octet_length('aeg-upstream-refresh-token-v2.'))
      = convert_to('aeg-upstream-refresh-token-v2.', 'UTF8');
```

The token size bound remains 256 KiB. Structured envelope plaintext is bounded
at 512 KiB, and the encoded envelope is bounded before decoding. Local signature,
codec and PostgreSQL tests cover finite cases; they do not prove cryptographic,
clock, isolation or complete distributed composition assumptions.

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
| `AEG_LOADTEST_SOURCE_SHA256` | required | `test` | Digest of the frozen source manifest associated with the actual binary. Required for all selections. |
| `AEG_LOADTEST_PROFILE_MANIFEST` | required for OAuth | `test` | Frozen activated client/issuer/policy/subject JSON receipt; no invented client defaults. |
| `AEG_LOADTEST_CLIENT_SECRET` | required for OAuth | `test` | Actual registered confidential-client secret; auth method is explicit in the profile manifest. |
| `AEG_LOADTEST_SESSION_FILE` | required for OAuth | `test` | Protected file containing the genuine public-login issuer cookie. Sent only to authorize. |
| `AEG_LOADTEST_SESSION_PROVENANCE` | required for OAuth | `test` | Protected producer receipt binding issuer, subject, profile digest and session digest. |
| `AEG_LOADTEST_CA_CERT` | system trust | `test` | Optional genuine PEM fixture CA; certificate/hostname validation remains enabled. |

The old client ID, redirect URI, scope and OIDC-scope defaults are replaced by
explicit profile-manifest fields. `AEG_LOADTEST_CLIENT_SECRET_POST`,
`AEG_LOADTEST_PROOF_ORIGIN`, and `AEG_LOADTEST_PUBLIC_ORIGIN` overrides are rejected.
Use the actual HTTPS issuer URL and supported TLS routing. See the
[load consumer contract](../../performance/README.md#load-consumer-inputs-and-reporting)
for profile/session schemas, supported RS256 ID Token validation, scenario
completeness, failure preservation and scenario-versus-HTTP reporting units.

## Source references

- Server config parsing: `crates/server/src/config.rs`
- Transport enforcement: `crates/server/src/middleware/tls.rs`
- OIDC config parsing: `crates/server/src/oidc/config.rs`
- DCR policy gates + SSA validation: `crates/server/src/dcr.rs`
- DCR persistence + bearer-token hash storage: `crates/server/src/dcr_persistence.rs`
- Runtime client snapshot synchronization: `crates/server/src/runtime_clients.rs`
- JWKS fetcher + caching: `crates/server/src/client_registry.rs`
- Request Object self-check: `crates/server/src/request_object.rs`

### Refresh response currentness and issued-at policy

Aegaeon rechecks the active runtime configuration and connection after the upstream
exchange, for both rotating and non-rotating responses. A short PostgreSQL
transaction holds shared locks on the runtime lifecycle/configuration rows and
connection and effective OAuth profile while checking the original issuer, client
ID, connection identifier, authentication method, encrypted credential snapshot
and resolved policy before applying the account-link generation CAS. Explicit
profile reassignment, default-profile replacement, expired/inactive profiles and
changes to the policy used for the request also reject the response.
The locks remain until commit; no lock is held during the network exchange.
If a conflicting management change commits first, refresh returns a generic
no-cache `409 invalid_grant` without returning new tokens or changing the grant
or last-use metadata. If refresh obtains the locks first, it may commit before
the management change. This checks current state, not the history of changes
that return all checked values to their originals.

For a supplied refreshed ID Token, Aegaeon additionally requires nonnegative
`iat` at or after the refresh HTTP request's start time minus the configured JWT
clock leeway. Existing signature, future-time, expiration and original-claim
checks still apply. This is a local RP freshness policy supporting the OP's
issuance-time requirement in [OIDC Core 1.0 errata set 2 §12.2](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse),
not a specification-defined mandatory RP age algorithm. Providers returning an
older ID Token can now receive `502 server_error`, even while its `exp` is valid.
Clock accuracy and the configured skew remain operational assumptions; replay
within that skew window or the same timestamp is not distinguishable. No new
configuration or envelope migration is needed. An absent ID Token remains valid.

The production lower-bound arithmetic is checked directly by
`upstream_refresh::freshness_full_numeric_domain` in Kani over every `i64` issued
at and `u64` start/leeway value against independent `i128` arithmetic. This does
not prove clocks, HTTP timestamp capture, SQL locking, cryptography, or complete
refresh composition. Signed-token and actual PostgreSQL regression tests cover
those implementation seams separately. Existing F* and Tamarin results retain
their stated abstractions and do not establish these new database guarantees.
