# Server Environment: OAuth And OIDC Runtime Settings

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This document is part of the split server environment-variable reference. Use this file for the detailed section below.

## Crypto profile / verification boundary

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_CRYPTO_PROFILE` | _removed_ | `environment` | Removed startup-environment fallback. In the supported PostgreSQL-backed runtime, `policy.cryptoProfile` is fixed to `verified`; startup rejects this environment variable when it is present. |

## OIDC runtime flags

In the supported PostgreSQL-backed runtime, OIDC behaviour is hydrated from the active management
Environment policy and `runtime_keys`. The `AEGAEON_OIDC_*` variables below are removed historical
startup-environment fallbacks. If any are configured for `aegaeon-server`, startup rejects them
before serving traffic.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_OIDC_ENABLED` | _removed_ | `environment` | Removed startup-environment fallback. In the supported PostgreSQL-backed runtime, `policy.oidcEnabled` is authoritative. |
| `AEGAEON_OIDC_ISSUER` | _removed_ | `environment` | Removed startup-environment fallback public issuer URL. In the supported PostgreSQL-backed runtime, the issuer is loaded from the Environment issuer host/URL. |
| `AEGAEON_OIDC_ID_TOKEN_TTL` | _removed_ | `environment` | Removed startup-environment fallback ID Token lifetime in seconds. In the supported PostgreSQL-backed runtime, `policy.idTokenTimeToLiveSeconds` is authoritative. |
| `AEGAEON_OIDC_ENABLE_DISCOVERY` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, exposes `/.well-known/openid-configuration`. In the supported PostgreSQL-backed runtime, `policy.oidcEnableDiscovery` is authoritative. |
| `AEGAEON_OIDC_ENABLE_USERINFO` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, exposes `/userinfo` (only when OIDC is enabled). The supported runtime loads managed profile claims from PostgreSQL. In the supported PostgreSQL-backed runtime, `policy.oidcEnableUserinfo` is authoritative. |
| `AEGAEON_OIDC_ENABLE_LOGOUT` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, exposes `/logout` (RP-initiated logout) and advertises `end_session_endpoint` in discovery. In the supported PostgreSQL-backed runtime, `policy.oidcEnableLogout` is authoritative. |
| `AEGAEON_OIDC_ENABLE_BACKCHANNEL_LOGOUT` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, `/logout` triggers Back-Channel Logout delivery to registered RPs (best-effort fan-out). In the supported PostgreSQL-backed runtime, `policy.oidcEnableBackchannelLogout` is authoritative. |
| `AEGAEON_OIDC_LOGOUT_SESSION_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. Retains logged-out sessions for stable logout `jti` reuse across Back-Channel Logout retries; entries are pruned after this TTL (seconds). In the supported PostgreSQL-backed runtime, `policy.oidcLogoutSessionTtlSeconds` is authoritative. |
| `AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL` | _unset_ | `system` | Redis URL for shared OIDC logout-session state (`sid`, client associations, and stable logout `jti` reuse). Required when OIDC is enabled in the supported server runtime. |
| `AEGAEON_OIDC_BACKCHANNEL_LOGOUT_TIMEOUT_SECS` | _removed_ | `environment` | Removed startup-environment fallback Back-Channel Logout HTTP timeout per RP request (seconds, 1-60). In the supported PostgreSQL-backed runtime, `policy.oidcBackchannelLogoutTimeoutSeconds` is authoritative. |
| `AEGAEON_OIDC_REQUIRE_NONCE` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, rejects OpenID requests missing `nonce` with `invalid_request`. In the supported PostgreSQL-backed runtime, `policy.oidcRequireNonce` is authoritative. |
| `AEGAEON_OIDC_SIGNING_BACKEND` | _removed_ | `environment` | Removed startup-environment fallback ID Token signing backend. Supported values were `local` and, when the `kms-aws` feature is enabled, `aws-kms`. Process-local signing is not allowed in the supported runtime; use `runtime_keys` usage `OIDC_ID_TOKEN_SIGNING` instead. |
| `AEGAEON_OIDC_SIGNING_KEY_PEM_FILE` | _removed_ | `environment` | Removed startup-environment fallback path to an RSA private key PEM used to sign ID Tokens (`alg=RS256`). In the supported PostgreSQL-backed runtime, the active `runtime_keys` `OIDC_ID_TOKEN_SIGNING` key is authoritative. |
| `AEGAEON_OIDC_SIGNING_KEY_PEM` | _removed_ | `environment` | Removed startup-environment fallback inline RSA private key PEM used to sign ID Tokens (`alg=RS256`). In the supported PostgreSQL-backed runtime, the active `runtime_keys` `OIDC_ID_TOKEN_SIGNING` key is authoritative. |
| `AEGAEON_OIDC_SIGNING_KID` | _removed_ | `environment` | Removed startup-environment fallback key ID (`kid`) advertised in JWKS and embedded in ID Token headers. In the supported PostgreSQL-backed runtime, `runtime_keys.kid` is authoritative. |
| `AEGAEON_OIDC_SIGNING_AWS_REGION` | _removed_ | `environment` | Removed startup-environment fallback AWS region used when `AEGAEON_OIDC_SIGNING_BACKEND=aws-kms`. Falls back to `AWS_REGION`; startup fails closed if neither is set. In the supported PostgreSQL-backed runtime, AWS KMS region is read from the runtime key provider configuration. |
| `AEGAEON_OIDC_SIGNING_AWS_KMS_KEY_ID` | _removed_ | `environment` | Removed startup-environment fallback AWS KMS key identifier/ARN used when `AEGAEON_OIDC_SIGNING_BACKEND=aws-kms`. Required for the AWS KMS signing backend. In the supported PostgreSQL-backed runtime, the runtime key handle is authoritative. |
| `AEGAEON_OIDC_JWKS_ADDITIONAL_FILE` | _removed_ | `environment` | Removed startup-environment fallback path to a JWKS JSON document (`{"keys":[...]}`) containing **additional public** RSA signing keys to publish for rotation overlap. In the supported PostgreSQL-backed runtime, RETIRING `OIDC_ID_TOKEN_SIGNING` runtime keys provide overlap JWKS. |
| `AEGAEON_OIDC_JWKS_ADDITIONAL` | _removed_ | `environment` | Removed startup-environment fallback inline JWKS JSON value used when `AEGAEON_OIDC_JWKS_ADDITIONAL_FILE` is unset. Duplicate `kid` values are rejected. In the supported PostgreSQL-backed runtime, RETIRING `OIDC_ID_TOKEN_SIGNING` runtime keys provide overlap JWKS. |
| `AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM_FILE` | _removed_ | `environment` | Removed startup-environment fallback optional path to an unencrypted **PKCS#8 RSA** private key PEM used to decrypt encrypted Request Objects (JWE, `alg=RSA-OAEP`, `enc=A256GCM`). Process-local key material is not allowed in the supported runtime; active `OIDC_REQUEST_OBJECT_DECRYPTION` runtime key material is used when present. |
| `AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM` | _removed_ | `environment` | Removed startup-environment fallback inline value used when `AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KEY_PEM_FILE` is unset. Process-local key material is not allowed in the supported runtime; active `OIDC_REQUEST_OBJECT_DECRYPTION` runtime key material is used when present. |
| `AEGAEON_OIDC_REQUEST_OBJECT_ENCRYPTION_KID` | _removed_ | `environment` | Removed startup-environment fallback key ID (`kid`) advertised in JWKS for Request Object encryption/decryption. Must not conflict with the signing key `kid`. In the supported PostgreSQL-backed runtime, `runtime_keys.kid` is authoritative. |

The supported PostgreSQL-backed runtime stores OIDC runtime key material in `aegaeon.runtime_keys`, not in
environment variables or the public `keyStore` configuration document. Use the management API
`POST /api/v1/teams/{teamId}/environments/{environmentId}/runtimeKeys` to create `databaseEncrypted`
`OIDC_ID_TOKEN_SIGNING` (`RS256`) or `OIDC_REQUEST_OBJECT_DECRYPTION`
(`RSA-OAEP+A256GCM`) keys from PKCS#8 RSA private key PEM. Responses and audit records include only
public metadata and derived public JWK. Use `runtimeKeys/activateNext` for usage-scoped promotion
and `runtimeKeys/{runtimeKeyId}/revoke` for revocation; changing the ACTIVE/RETIRING runtime-key set
is monitor-visible and causes management-database nodes to restart rather than continue serving
stale key material.

## private_key_jwt and request objects (JAR)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ENABLE_PRIVATE_KEY_JWT` | _removed_ | `environment` | Removed startup-environment fallback. Enables `private_key_jwt` client authentication on `/token`. In the supported PostgreSQL-backed runtime, `policy.privateKeyJwtEnabled` is authoritative. |
| `AEGAEON_CLIENT_JWT_ALLOWED_ALGS` | _removed_ | `environment` | Removed startup-environment fallback comma-separated allow-list for client assertion algorithms (applies to `private_key_jwt` and JWT bearer assertions). In the supported PostgreSQL-backed runtime, `policy.clientJwtAllowedAlgs` is authoritative. The promoted server claim covers the narrow `RS256 Interop Slice`; broad RSA and non-promoted interoperability surfaces remain outside the verified allowlist. |
| `AEGAEON_CLIENT_JWT_REQUIRE_KID` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, requires a `kid` header in `private_key_jwt` and JWT bearer assertions, plus DCR metadata. In the supported PostgreSQL-backed runtime, `policy.clientJwtRequireKid` is authoritative. |
| `AEGAEON_JWT_LEEWAY_SECS` | _removed_ | `environment` | Removed startup-environment fallback clock skew leeway (seconds) when validating client assertions, request objects, and JWT bearer assertions (`exp`/`nbf`). In the supported PostgreSQL-backed runtime, `policy.jwtLeewaySeconds` is authoritative. |
| `AEGAEON_PKJWT_JTI_WINDOW_SECS` | _removed_ | `environment` | Removed startup-environment fallback replay window (seconds, valid range 1-3600) for `private_key_jwt` `jti` values. In the supported PostgreSQL-backed runtime, `policy.pkjwtJtiWindowSeconds` is authoritative. |
| `AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL` | _unset_ | `system` | Redis URL for client-assertion replay stores (`private_key_jwt` and JWT bearer). Startup fails closed when the surface is required and this URL is unset. |
| `AEGAEON_REQUEST_OBJECT_JTI_TTL` | _removed_ | `environment` | Removed startup-environment fallback replay window (seconds, valid range 1-3600) for Request Object (`request`) `jti` values. In the supported PostgreSQL-backed runtime, `policy.requestObjectJtiTtlSeconds` is authoritative. |
| `AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL` | _unset_ | `system` | Redis URL for Request Object (`request`) `jti` replay protection. Startup fails closed when this surface is required and the URL is unset. |
| `AEGAEON_REQUEST_OBJECT_EVERPARSE_RUNTIME` | _removed_ | `environment` | Removed startup-environment fallback for the optional defense-in-depth Request Object EverParse self-check. In the supported PostgreSQL-backed runtime, `policy.requestObjectEverparseRuntimeEnabled` is authoritative. The self-check validates a canonical binary encoding of already-validated Request Object claims and does **not** validate raw JWT input. |

## JWT bearer grant (RFC 7523)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ENABLE_JWT_BEARER_GRANT` | _removed_ | `environment` | Removed startup-environment fallback. Enables the JWT bearer authorization grant on `/token`. In the supported PostgreSQL-backed runtime, `policy.allowedGrantTypes` is authoritative and must include `urn:ietf:params:oauth:grant-type:jwt-bearer`. |
| `AEGAEON_JWT_BEARER_ALLOW_CLIENT_SUBJECT` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, allows `sub == client_id` only when the assertion audience targets the issuer (`{issuer}`) and excludes `{issuer}/token`. In the supported PostgreSQL-backed runtime, `policy.jwtBearerAllowClientSubject` is authoritative. |
| `AEGAEON_JWT_BEARER_JTI_WINDOW_SECS` | _removed_ | `environment` | Removed startup-environment fallback replay window (seconds, valid range 1-3600) for JWT bearer `jti` values. In the supported PostgreSQL-backed runtime, `policy.jwtBearerJtiWindowSeconds` is authoritative. |

## Token exchange (RFC 8693)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ENABLE_TOKEN_EXCHANGE` | _removed_ | `environment` | Removed startup-environment fallback. Enables the token exchange grant on `/token`. In the supported PostgreSQL-backed runtime, `policy.allowedGrantTypes` is authoritative and must include `urn:ietf:params:oauth:grant-type:token-exchange`. |

## JWT access tokens / JWT introspection response

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ENABLE_JWT_ACCESS_TOKENS` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, access tokens are issued as JWTs (RFC 9068). In the supported PostgreSQL-backed runtime, `policy.jwtAccessTokensEnabled` is authoritative. |
| `AEGAEON_ENABLE_JWT_INTROSPECTION` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, `/introspect` can return JWT responses when the client requests `application/token-introspection+jwt` (RFC 9701). In the supported PostgreSQL-backed runtime, `policy.jwtIntrospectionEnabled` is authoritative. |
| `AEGAEON_JWT_INTROSPECTION_EXP_SECS` | _removed_ | `environment` | Removed startup-environment fallback max lifetime (seconds, valid range 1-60) for JWT introspection responses. In the supported PostgreSQL-backed runtime, `policy.jwtIntrospectionExpSeconds` is authoritative. |

In the supported PostgreSQL-backed runtime, JWT access tokens and JWT introspection responses use
active `runtime_keys` entries with usages `JWT_ACCESS_TOKEN_SIGNING` and
`JWT_INTROSPECTION_SIGNING`. `RETIRING` keys remain published in JWKS and accepted for verification
overlap. Server-local generated signing keys are not a supported runtime key path.

## Device authorization (RFC 8628)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ENABLE_DEVICE_AUTHZ` | _removed_ | `environment` | Removed startup-environment fallback. Enables the device authorization grant. In the supported PostgreSQL-backed runtime, `policy.allowedGrantTypes` is authoritative and must include `urn:ietf:params:oauth:grant-type:device_code`. |
| `AEGAEON_DEVICE_CODE_REDIS_URL` | _unset_ | `system` | Redis URL for shared device authorization codes, user-code lookup state, poll backoff, and single-use approval consumption. Required by the supported server runtime. |
| `AEGAEON_DEVICE_CSRF_REDIS_URL` | _unset_ | `system` | Redis URL for device-verification CSRF tokens. Startup fails closed when this surface is required and the URL is unset. |
| `AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL` | _unset_ | `system` | Redis URL for device-verification rate-limit buckets. Startup fails closed when this surface is required and the URL is unset. |

## JWKS fetching (for `jwks_uri`)

JWKS fetch policy is split between issuer-scoped management policy and host-local bootstrap
settings. Runtime policy fields are persisted in PostgreSQL; the old startup-environment policy
variables are retained below only as a negative inventory and are rejected when present. Host-local
trust, Redis, and observability settings remain process environment because they describe the node
boundary rather than issuer policy. JWKS body caching is bounded, process-local, and
non-authoritative; Redis remains the shared runtime-state boundary.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_JWKS_CACHE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksCacheTtlSeconds` is authoritative. |
| `AEGAEON_JWKS_REFRESH_SKEW_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksRefreshSkewSeconds` is authoritative. |
| `AEGAEON_JWKS_HTTP_TIMEOUT_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksHttpTimeoutSeconds` is authoritative. |
| `AEGAEON_JWKS_HTTP_RETRIES` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksHttpRetries` is authoritative. |
| `AEGAEON_JWKS_MAX_BODY_BYTES` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksMaxBodyBytes` is authoritative. |
| `AEGAEON_JWKS_INSECURE_SKIP_VERIFY` | `0` | `system` | If enabled, disables TLS certificate verification (tests only). |
| `AEGAEON_JWKS_CA_BUNDLE` | _unset_ | `system` | Path to a PEM CA bundle to trust for JWKS fetches. |
| `AEGAEON_JWKS_CIRCUIT_OPEN_FAILS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksCircuitOpenFails` is authoritative. |
| `AEGAEON_JWKS_CIRCUIT_RESET_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksCircuitResetSeconds` is authoritative. |
| `AEGAEON_JWKS_REDIS_URL` | _unset_ | `system` | Redis URL for shared JWKS runtime state: circuit breaker phase/failure/probe state and `kid` fingerprint history. Required by the supported shared-store preflight. |
| `AEGAEON_JWKS_SHARED_CACHE_PATH` | _removed_ | `environment` | Removed on-disk JWKS body cache. In the supported runtime, `AEGAEON_JWKS_REDIS_URL` is the shared runtime-state boundary. |
| `AEGAEON_JWKS_SHARED_CACHE_GC_INTERVAL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksCacheGcIntervalSeconds` is authoritative. |
| `AEGAEON_JWKS_SHARED_CACHE_MAX_AGE_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksSharedStateMaxAgeSeconds` is authoritative. |
| `AEGAEON_JWKS_STALE_IF_ERROR_SECS` | _removed_ | `environment` | Removed startup-environment fallback. JWKS stale serving is not part of the supported runtime. |
| `AEGAEON_JWKS_STALE_MEMORY_MAX_SECS` | _removed_ | `environment` | Removed startup-environment fallback. JWKS stale serving is not part of the supported runtime. |
| `AEGAEON_JWKS_STALE_SHARED_MAX_SECS` | _removed_ | `environment` | Removed with the on-disk shared JWKS body cache. No replacement policy field exists. |
| `AEGAEON_JWKS_STALE_PREFERENCE` | _removed_ | `environment` | Removed with the on-disk shared JWKS body cache. No replacement policy field exists. |
| `AEGAEON_JWKS_STALE_MAX_GENERATIONS` | _removed_ | `environment` | Removed startup-environment fallback. No replacement policy field exists. |
| `AEGAEON_JWKS_REQUIRE_PIN_ON_STALE` | _removed_ | `environment` | Removed startup-environment fallback. No replacement policy field exists. |
| `AEGAEON_JWKS_ALLOW_KID_REUSE` | _removed_ | `environment` | Removed startup-environment fallback. In the supported runtime, `policy.jwksAllowKidReuse` is authoritative. |
| `AEGAEON_JWKS_LOG_SAMPLE_PERCENT` | `5` | `system` | Sampling rate (0-100) for JWKS event logs. |
| `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200` | _unset_ | `system` | Optional sampling override (0-100) for successful `200` JWKS fetch event logs. Falls back to `AEGAEON_JWKS_LOG_SAMPLE_PERCENT`. |
| `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304` | _unset_ | `system` | Optional sampling override (0-100) for `304 Not Modified` JWKS fetch event logs. Falls back to `AEGAEON_JWKS_LOG_SAMPLE_PERCENT`. |
| `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE` | _unset_ | `system` | Optional sampling override (0-100) for failed JWKS fetch event logs. Falls back to `AEGAEON_JWKS_LOG_SAMPLE_PERCENT`. |
| `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR` | _unset_ | `system` | Optional sampling override (0-100) for JWKS fetch internal error event logs. Falls back to `AEGAEON_JWKS_LOG_SAMPLE_PERCENT`. |
| `AEGAEON_JWKS_HISTOGRAM_BUCKETS` | `0.01,0.025,0.05,0.1,0.25,0.5,1.0` | `system` | Override Prometheus histogram buckets for JWKS HTTP latency. |

Outcome-specific log sampling overrides are supported via:

- `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_<OUTCOME>`

Where `<OUTCOME>` is the uppercased outcome label accepted by the JWKS fetcher:
`200`, `304`, `FAILURE`, or `ERROR`.

## Dynamic Client Registration (DCR) and SSA verification

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_DCR_BEARER_TOKEN` | _removed_ | `environment` | Removed startup-environment fallback. In the supported PostgreSQL-backed runtime, configure this through the environment `dcrBearerToken` management endpoint; the authoritative value is a SHA-256 hash in `aegaeon.environment_dcr_bearer_tokens`, and management API writes enforce the same minimum. Startup rejects this variable when it is present. |
| `AEGAEON_SSA_JWT_PEM` | _removed_ | `environment` | Removed startup-environment fallback RSA public key (PEM) used to verify incoming SSA JWTs for DCR. If unset, SSA verification is not configured. In the supported PostgreSQL-backed runtime, `policy.ssaJwtPem` is authoritative. |
| `AEGAEON_SSA_EXPECTED_ISS` | _removed_ | `environment` | Removed startup-environment fallback expected SSA issuer. If set, requires SSA `iss` to match. In the supported PostgreSQL-backed runtime, `policy.ssaExpectedIss` is authoritative. |
| `AEGAEON_SSA_EXPECTED_AUD` | _removed_ | `environment` | Removed startup-environment fallback expected SSA audience. If set, requires SSA `aud` to match (typically the full registration endpoint URL). In the supported PostgreSQL-backed runtime, `policy.ssaExpectedAud` is authoritative. |
| `AEGAEON_SSA_LEEWAY_SECS` | _removed_ | `environment` | Removed startup-environment fallback clock skew leeway (seconds) for SSA `exp`/`nbf`. In the supported PostgreSQL-backed runtime, `policy.ssaLeewaySeconds` is authoritative. |
| `AEGAEON_DCR_REQUIRE_PKCE_FOR_PUBLIC` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, public clients must explicitly declare PKCE required in metadata (policy gate). In the supported PostgreSQL-backed runtime, `policy.dcrRequirePkceForPublic` is authoritative. |
| `AEGAEON_DCR_REQUIRE_PKCE_FOR_CONFIDENTIAL` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, confidential clients must explicitly declare PKCE required in metadata (policy gate). In the supported PostgreSQL-backed runtime, `policy.dcrRequirePkceForConfidential` is authoritative. |
| `AEGAEON_DCR_REQUIRE_SENDER_CONSTRAINED` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, clients must declare sender-constrained tokens (policy gate). In the supported PostgreSQL-backed runtime, `policy.dcrRequireSenderConstrained` is authoritative. |
| `AEGAEON_DCR_ALLOWED_SENDER_METHODS` | _removed_ | `environment` | Removed startup-environment fallback allowed sender-constrained methods (comma-separated). In the supported PostgreSQL-backed runtime, `policy.dcrAllowedSenderMethods` is authoritative. |
| `AEGAEON_DCR_EVERPARSE_RUNTIME` | _removed_ | `environment` | Removed startup-environment fallback for the optional defense-in-depth DCR EverParse self-check. In the supported PostgreSQL-backed runtime, `policy.dcrEverparseRuntimeEnabled` is authoritative. The self-check validates a canonical binary encoding of already-parsed DCR metadata and does **not** validate raw RFC 7591 JSON. |

`/register` and `/register/{client_id}` are exposed only when the active database policy has
`policy.dcrEnabled=true`; otherwise metadata omits `registration_endpoint` and the DCR routes return
JSON 404. When enabled, the routes use the issuer-scoped PostgreSQL-backed DCR registry in the
supported PostgreSQL-backed runtime and refresh the in-process runtime snapshot after each mutation.
The local snapshot remains an optimization; PostgreSQL is the authoritative registry, and the
monitor exits if a node cannot converge to the DB projection.

## PAR (Pushed Authorization Requests)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_PAR_EXPIRES_IN` | _removed_ | `environment` | Removed startup-environment fallback `expires_in` for `request_uri` values (seconds, valid range 1-600). In the supported PostgreSQL-backed runtime, `policy.parExpiresInSeconds` is authoritative. |
| `AEGAEON_PAR_REDIS_URL` | _unset_ | `system` | Redis URL for shared PAR `request_uri` storage. Required by the supported server runtime so reservation and consumption are coordinated outside process memory. |
