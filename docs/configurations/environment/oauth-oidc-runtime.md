# Server Environment: OAuth And OIDC Runtime Settings

Last updated: 2026-10-02

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

## Browser endpoint query admission

`/authorize` and `/logout` use strict form decoding for GET and implicit HEAD
queries. Percent escapes must be complete hexadecimal pairs and the decoded
text must be valid UTF-8 ([RFC 6749 Appendix B](https://www.rfc-editor.org/rfc/rfc6749#appendix-B)).
`+` decodes to a space; `%2B` decodes to a literal plus.

Empty values are treated as omitted. Unknown parameters, including repeated
unknown names, are ignored after decoding and size checks. Repeated recognized
singleton parameters are rejected, including encoded spellings of the same name
([RFC 6749 section 3.1](https://www.rfc-editor.org/rfc/rfc6749#section-3.1)).
Repeated `resource` values reach the existing single-resource policy and return
`invalid_target`; they are not silently collapsed.

Limits remain 16 KiB of raw query, 64 nonempty encoded parameters, 64 decoded
bytes per name and 8 KiB per value. Ignored and empty parameters count toward
these limits. Transport and URI credential checks still apply. Admission errors
return no-cache `invalid_request` responses without echoing supplied values.
Clients that relied on replacement-character decoding must send valid UTF-8;
no server configuration or database migration is required.

## Authorization configuration snapshots

Each authorization request reads the selected client, its effective OAuth
profile, active configuration and runtime key facts in one read-only
`REPEATABLE READ` transaction. An explicit inactive or expired profile remains
an error; it cannot fall back to the default profile. Expiry checks use the
transaction's time. The transaction ends before remote JAR key lookup or PAR
reservation, and later validation, consent processing and error redirects use
the selected client view for that request. A subsequent request reads fresh
client and profile data.

If the environment, issuer, configuration or runtime keys no longer match the
loaded startup configuration, authorization returns no-cache HTTP 503
`temporarily_unavailable` after query parsing and before JAR/PAR processing.
Existing runtime restart and readiness behavior still applies. This snapshot
bounds authorization input selection; it does not lock the database for later
code issuance or make that issuance atomic with concurrent management changes.

Rust integrations must construct `DatabaseRuntimeConfiguration` with
`load_database_runtime_configuration`, derive an `AuthorizationRuntime`, and
use its configuration and OIDC instances with
`RuntimeAuthorityState::from_authorization_runtime`. The retained loader source
is private, so external struct literals are no longer supported. Independently
assembled or replaced configuration instances cannot serve authorization.
No database migration or new environment setting is required.

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

`policy.jwksHttpTimeoutSeconds` bounds waiting for each explicit HTTP request
and each blocking body read; it is not a total acquisition deadline. A redirect
chain follows at most two HTTPS redirects. Conditional revalidation never follows
a redirect: an unusable `304` or usable redirect can trigger one unconditional
recovery from the registered URI. `policy.jwksHttpRetries` is one shared ordinary
transport/server-error budget across those phases and all redirect hops. A single
acquisition captures its TLS trust and system proxy configuration once.

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

New registrations default to `authorization_code` only; refresh must be requested
explicitly. Code grants require nonempty redirects and `["code"]` responses;
non-code grants use `[]` responses and may omit redirects. Owner updates preserve
omitted/null response sets, including `[]`, so grant transitions require matching
explicit responses. Duplicate grants/redirects, raw ASCII whitespace/control in
URIs, dual key sources, and `none` authentication with client credentials or token
exchange are rejected. See the [metadata upgrade runbook](../../operations/registration-metadata-upgrade.md)
for management synchronization, SQL and strict local all-row preflight, versioned schema requirements,
predecessor repair and captured-authorization effects.

The DCR self-check is required when `policy.dcrEverparseRuntimeEnabled` is enabled
or the server is built with `verified-claim`. A required unavailable or rejecting
native parser produces an internal registration error. The check encodes a
projection of parsed metadata into a length-prefixed binary buffer; it checks that
buffer's structure, not the original JSON or all grant/response relationships.
The runtime grant mask uses `0x1` for authorization code, `0x2` for refresh,
`0x4` for client credentials, `0x8` for JWT bearer, `0x10` for token exchange and
`0x20` for the RFC 8628 device grant. Combinations preserve each bit. These are
internal representation values, not OAuth wire values. The generated parser's
`UINT32` grant field accepts this representation without a layout change;
registration and device endpoint policy checks still determine admission.

## PAR (Pushed Authorization Requests)

Plain `/par` forms require `client_id` even with Basic or assertion authentication.
A signed Request Object may supply the authorization `client_id` internally;
its verified value must match the authenticated client. See
[client assertion identification](../../operations/private-key-jwt.md#client-identification).

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_PAR_EXPIRES_IN` | _removed_ | `environment` | Removed startup-environment fallback `expires_in` for `request_uri` values (seconds, valid range 1-600). In the supported PostgreSQL-backed runtime, `policy.parExpiresInSeconds` is authoritative. |
| `AEGAEON_PAR_REDIS_URL` | _unset_ | `system` | Redis URL for shared PAR `request_uri` storage. Required by the supported server runtime so reservation and consumption are coordinated outside process memory. |

## OAuth form admission

At `/token`, `/par`, `/device_authorization`, `/introspect`, and `/revoke`,
zero-length decoded form values are omitted before field typing, authentication,
and extension parsing (RFC 6749 sections 3.1 and 3.2). Thus `scope=` and a
valueless `scope` behave as omission; `scope=&scope=api.read` has one effective
value. Two nonempty recognized singleton occurrences reject, including encoded
spellings of the same name. Unknown parameters are ignored where permitted;
Request Object PAR still excludes effective outer authorization fields.
Repeated `resource` and `audience` values retain the endpoint's target resolver
rules. Empty `max_age` at PAR is absent, not a numeric conversion error.

Whitespace is nonempty. Client identifiers and supported `grant_type` values
are compared exactly, including extension URIs. Refresh/device tokens, JWT grant
assertions, and token-exchange subject tokens are not trimmed before validation.
Resource URIs reject raw whitespace/control characters and retain valid input
spelling, including percent-encoded characters, without URL canonicalization. Clients that sent upper-case
or padded grant types must send the registered spelling. Supported authorization
`response_mode` values are exactly `query` and `form_post`; omitted or empty OAuth
parameters select `query`. Request Object JSON claim typing is unchanged, and
an empty JSON response-mode string remains invalid.

Empty form credentials do not add an authentication method. Basic with
`client_id=&client_secret=` behaves like Basic without those form parameters;
an empty Basic password remains an authentication attempt. If both assertion
form values are empty, both are absent. Nonempty incomplete, malformed, or
whitespace assertion credentials still reject without falling back to a public
client. Required effective values remain required, including plain PAR's
`client_id`, token requests' `grant_type`, and lifecycle requests' `token`.

The existing Axum form decoder, 2 MiB raw request-body limit, method and transport
gates are unchanged: empty and ignored fields still occupy raw body bytes.
These five form entrances have no separate raw parameter-count limit. Browser
authorization retains its own admission limits. Local login, password, CSRF,
and management forms do not use this OAuth omission rule. These runtime changes
and finite route tests do not extend formal proof coverage.

## OAuth grant error categories

After form admission, client authentication and profile lookup, `/token` rejects
unknown grant identifiers with HTTP 400 `unsupported_grant_type` (RFC 6749
section 5.2). Recognition uses the exact wire spelling of the six dispatched
grants; password, case variants, padded identifiers and unknown extension URIs
are unsupported. Missing or empty `grant_type` remains `invalid_request`.
A supported grant denied by the applicable client/profile allowlist remains
`unauthorized_client`; disabled extension checks retain `unsupported_grant_type`
when reached. This distinction does not change configuration activation or
allowlist defaults.

A validly authenticated client presenting another client's authorization code
receives HTTP 400 `invalid_grant`. This refusal leaves the code available for its
owner, who must still satisfy redirect, PKCE and all other grant checks. A live
device code presented by another client also returns `invalid_grant` without
changing poll timing, backoff, approval or consumption (RFC 8628 section 3.5).
Wrong-environment device lookups remain indistinguishable from expired codes.
Pending, slow-down, denial, expiration and resource-target errors keep their
existing categories; success consumes the approved device code once.

The public Rust `DevicePollResult` enum adds `InvalidGrant`; downstream exhaustive
matches must handle this variant. Stored device records and database schemas do
not change, and no data migration is required. Finite PostgreSQL/Redis route
tests and process-local store tests cover these distinctions; they do not extend
formal proof coverage or establish complete error-profile conformance.
