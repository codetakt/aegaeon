# Server Environment: Network And Runtime Policy Settings

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This document is part of the split server environment-variable reference. Use this file for the detailed section below.

## Transport security (reverse proxy / forwarded headers)

When enabled, the transport middleware enforces:

1) the request came from a trusted proxy (`AEGAEON_TRUSTED_PROXIES`), and
2) `proto=https` is present in `Forwarded` or `X-Forwarded-Proto`.

For multi-hop forwarding headers, Aegaeon accepts at most `AEGAEON_ALLOW_PROXY_CHAIN_LENGTH`
entries and uses the nearest/rightmost hop. The same trusted-proxy boundary is used when deriving
rate-limit subjects for login, device-verification, management-login, and Federation public
endpoints. `Forwarded for=` is used only after trusted-proxy validation; `X-Forwarded-For` is not
trusted.

Note: `AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY=1` forces this enforcement on unless you explicitly disable
the policy gate.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_TRUSTED_PROXIES` | `127.0.0.1,::1` | `system` | Comma-separated IPs/CIDRs that are trusted to set forwarding headers. |
| `AEGAEON_REQUIRE_TLS_PROXY` | _unset_ | `system` | If set, directly controls TLS-proxy enforcement. |
| `AEGAEON_ENFORCE_SECURE_PROTO` | _removed_ | `system` | Removed legacy TLS-proxy toggle. Startup fails closed if this variable is present; use `AEGAEON_REQUIRE_TLS_PROXY`. |
| `AEGAEON_ALLOW_PROXY_CHAIN_LENGTH` | `1` | `system` | Maximum accepted `Forwarded` / `X-Forwarded-Proto` hop count (min 1). The nearest/rightmost hop is used; longer chains fail closed. |
| `AEGAEON_REQUIRE_MTLS_FROM_PROXY` | `0` | `system` | If enabled, requires `x-forwarded-client-cert` to contain a valid SHA-256 fingerprint (proxy mTLS). |
| `AEGAEON_FORWARD_HEADER_LOG_VALUES` | `0` | `system` | If enabled, logs sanitized `Forwarded` / `X-Forwarded-Proto` values for debugging. |

## Global security policy (RFC 9700 operator gates)

Issuer-scoped runtime policy is loaded from PostgreSQL. Removed startup-environment policy
variables are retained in this table only as a negative inventory: if set, server startup rejects
them before serving traffic. The only active process-environment settings in this section are the
transport-boundary system settings `AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY` and
`AEGAEON_POLICY_REQUIRE_TLS_VALIDATION`, which are read during bootstrap because they protect the
process/proxy boundary rather than an issuer policy snapshot.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY` | `1` | `system` | Enables strict forwarded/TLS checks (transport middleware). This bootstrap setting protects the process/proxy boundary before database policy hydration. Set to `0` only for direct HTTP local development. |
| `AEGAEON_POLICY_REQUIRE_TLS_VALIDATION` | `1` | `system` | Transport hardening invariant. This bootstrap setting is read before database policy hydration; only true values are accepted, and false values fail startup. |
| `AEGAEON_POLICY_REQUIRE_SCOPE_SUBSET` | _removed_ | `environment` | Removed startup-environment fallback. The active database policy keeps the hardened default. |
| `AEGAEON_POLICY_REQUIRE_AUDIENCE_MATCH` | _removed_ | `environment` | Removed startup-environment fallback. The active database policy keeps the hardened default. |
| `AEGAEON_POLICY_ENFORCE_SENDER_BINDING` | _removed_ | `environment` | Removed startup-environment fallback. Sender binding is derived from the active policy/profile and OAuth profile constraints. |
| `AEGAEON_POLICY_RETAIN_REFRESH_CHAIN` | _removed_ | `environment` | Removed startup-environment fallback. The active database policy keeps the hardened default. |
| `AEGAEON_POLICY_ALLOW_IMPLICIT` | _removed_ | `environment` | Removed startup-environment fallback. Managed OAuth profiles are the explicit review boundary for any compatibility exception. |
| `AEGAEON_POLICY_ALLOW_ROPC` | _removed_ | `environment` | Removed startup-environment fallback. Managed OAuth profiles are the explicit review boundary for any compatibility exception. |
| `AEGAEON_POLICY_REQUIRE_PKCE` | _removed_ | `environment` | Removed startup-environment fallback. `policy.pkceRequired` and managed OAuth profiles are authoritative. |
| `AEGAEON_POLICY_SENDER_CONSTRAINT` | _removed_ | `environment` | Removed startup-environment fallback. The active policy/profile is authoritative. |

## DPoP verification (RFC 9449)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_REQUIRE_DPOP_NONCE` | _removed_ | `environment` | Removed startup-environment fallback for server-issued DPoP nonce enforcement (RFC 9449 Section 5). In the supported PostgreSQL-backed runtime, `policy.dpopRequireNonce` is authoritative. |
| `AEGAEON_DPOP_NONCE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback TTL (seconds, valid range 1-3600) for DPoP nonces. In the supported PostgreSQL-backed runtime, `policy.dpopNonceTtlSeconds` is authoritative and Redis stores issued nonces until that TTL. |
| `AEGAEON_DPOP_REDIS_URL` | _unset_ | `system` | Redis URL for the shared DPoP replay store. The supported server process always constructs this store; startup fails closed when it is missing. |
| `AEGAEON_DPOP_NONCE_REDIS_URL` | _unset_ | `system` | Redis URL for shared DPoP nonce validation. Startup fails closed when nonce enforcement is enabled and this URL is unset. |
| `AEGAEON_DPOP_STRICT` | _removed_ | `environment` | Removed startup-environment fallback. If the global sender-constraint policy is `None`, strict mode upgrades the runtime posture to DPoP and enables sender-binding enforcement. In the supported PostgreSQL-backed runtime, `policy.dpopStrict` is authoritative. |
| `AEGAEON_DPOP_IAT_WINDOW_SECS` | _removed_ | `environment` | Removed startup-environment fallback maximum absolute age/skew window for the DPoP `iat` claim, in seconds. Valid range is `1..=300`. In the supported PostgreSQL-backed runtime, `policy.dpopIatWindowSeconds` is authoritative. |

## Authorization endpoint behaviour

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_REQUIRE_STATE` | _removed_ | `environment` | Removed startup-environment fallback. Requires a non-empty `state` parameter on `/authorize`. In the supported PostgreSQL-backed runtime, `policy.requireStateParameter` is authoritative. |
| `AEGAEON_STRICT_AUTHORIZE_REDIRECT` | _removed_ | `environment` | Removed startup-environment fallback. If enabled, `/authorize` errors redirect to the registered `redirect_uri` (302). If disabled, errors return JSON with HTTP 400. In the supported PostgreSQL-backed runtime, `policy.strictAuthorizeRedirect` is authoritative. |
| `AEGAEON_ALLOW_DEMO_AUTHORIZE_LOGIN` | `0` | `test` | Enables the demo `/authorize` login shortcut. Keep disabled outside local demos/tests; normal deployments should use the server-handled credential surfaces. |
| `AEGAEON_AUTHORIZATION_CODE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback authorization code lifetime in seconds (valid range 1-600). In the supported PostgreSQL-backed runtime, `policy.authorizationCodeTimeToLiveSeconds` is authoritative. |
| `AEGAEON_STATE_NONCE_TTL_SECS` | _removed_ | `environment` | Removed legacy alias. It is no longer read as a fallback; the supported runtime uses `policy.authorizationCodeTimeToLiveSeconds` and rejects this startup-managed policy variable when it is set. |
| `AEGAEON_AUTH_CODE_REDIS_URL` | _unset_ | `system` | Redis URL for shared authorization-code, `state`, and `nonce` storage. Must match `AEGAEON_TOKEN_STORE_REDIS_URL` so authorization-code exchange can consume the code and commit issued tokens atomically. |

## Token lifetimes

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ACCESS_TOKEN_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback access token lifetime in seconds. In the supported PostgreSQL-backed runtime, `policy.accessTokenTimeToLiveSeconds` is authoritative. |
| `AEGAEON_REFRESH_TOKEN_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback refresh token lifetime in seconds. In the supported PostgreSQL-backed runtime, `policy.refreshTokenTimeToLiveSeconds` is authoritative. |
| `AEGAEON_TOKEN_STORE_REDIS_URL` | _unset_ | `system` | Redis URL for shared access-token, refresh-token, bearer metadata, and revocation state. Must match `AEGAEON_AUTH_CODE_REDIS_URL` so authorization-code exchange can consume the code and commit issued tokens atomically. |

## Local end-user authentication

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_AUTH_SESSION_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback for local end-user auth-session cookie lifetime in seconds (valid range 1-86400). In the supported PostgreSQL-backed runtime, `policy.authSessionTtlSeconds` is authoritative. |
| `AEGAEON_AUTH_MAX_SESSIONS` | _removed_ | `environment` | Removed startup-environment fallback for the maximum number of local end-user auth sessions retained in the selected backend (valid range 1-1000000). In the supported PostgreSQL-backed runtime, `policy.authMaxSessions` is authoritative. |
| `AEGAEON_AUTH_SESSION_REDIS_URL` | _unset_ | `system` | Redis URL for shared browser auth sessions. Required by the supported server runtime serving local or upstream browser login flows. |
| `AEGAEON_CSRF_REDIS_URL` | _removed_ | `system` | Removed shared Redis fallback for CSRF token stores. Configure each CSRF surface Redis URL explicitly; startup fails closed if this variable is present. |
| `AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL` | _unset_ | `system` | Redis URL for local end-user authentication CSRF tokens. Startup fails closed when this surface is required and the URL is unset. |
| `AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL` | _unset_ | `system` | Redis URL for local end-user login rate-limit buckets. Startup fails closed when this surface is required and the URL is unset. |
| `AEGAEON_LOCAL_PASSWORD_ACR` | _removed_ | `environment` | Removed startup-environment fallback ACR value assigned to successful local password authentication. In the supported PostgreSQL-backed runtime, `policy.localPasswordAcr` is authoritative. If supported ACR values are configured, this value must be present in that allow-list. |

## Step-up authentication (RFC 9470)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_ACR_VALUES_SUPPORTED` | _removed_ | `environment` | Removed startup-environment fallback comma-separated allow-list of supported ACR values. In the supported PostgreSQL-backed runtime, `policy.acrValuesSupported` is authoritative. When unset/empty, `acr_values` requests are rejected and `acr_values_supported` is omitted from OAuth/OIDC metadata. |
| `AEGAEON_DEFAULT_ACR` | _removed_ | `environment` | Removed startup-environment fallback default ACR assigned when no `acr_values` is requested. In the supported PostgreSQL-backed runtime, `policy.defaultAcr` is authoritative. If supported ACR values are configured, this value must be present in that allow-list. |
| `AEGAEON_STEPUP_CHALLENGE_TTL_SECS` | _removed_ | `environment` | Removed startup-environment fallback TTL (seconds, valid range 1-600) for step-up challenges. In the supported PostgreSQL-backed runtime, `policy.stepupChallengeTtlSeconds` is authoritative. |
| `AEGAEON_STEPUP_REDIS_URL` | _unset_ | `system` | Redis URL for shared step-up challenges, request lookup state, completion, and single-use consumption. Required by the supported server runtime. |

## Rich Authorization Requests (RFC 9396)

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_AUTHORIZATION_DETAILS_TYPES_SUPPORTED` | _removed_ | `environment` | Removed startup-environment fallback comma-separated allow-list of `authorization_details` `type` values. In the supported PostgreSQL-backed runtime, `policy.authorizationDetailsTypesSupported` is authoritative. If unset or empty, the server rejects `authorization_details` with `invalid_authorization_details` and omits `authorization_details_types_supported` from metadata. |

## Background cleanup tasks

The server runs a periodic cleanup loop for runtime stores that expose local expiry cleanup. The
supported server process requires PostgreSQL plus Redis-backed shared runtime stores; process-local
cleanup remains limited to unit tests, fuzz/protocol harnesses, and explicit debug helpers.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_CLEANUP_INTERVAL_SECS` | _removed_ | `environment` | Removed startup-environment fallback. In the supported PostgreSQL-backed runtime, `policy.cleanupIntervalSeconds` is authoritative and startup rejects this variable when it is present. |

## Client authentication requirements

These toggles enforce client authentication (Basic / client_secret_post and, when enabled,
`private_key_jwt`) for the relevant endpoints.

| Variable | Default | Scope | Notes |
| --- | --- | --- | --- |
| `AEGAEON_REQUIRE_CLIENT_AUTH_TOKEN` | _removed_ | `environment` | Removed startup-environment fallback. Requires client auth on `/token` for confidential clients. In the supported PostgreSQL-backed runtime, `policy.requireClientAuthToken` is authoritative. |
| `AEGAEON_REQUIRE_CLIENT_AUTH_PAR` | _removed_ | `environment` | Removed startup-environment fallback. Requires client auth on `/par`. In the supported PostgreSQL-backed runtime, `policy.requireClientAuthPar` is authoritative. |
| `AEGAEON_REQUIRE_CLIENT_AUTH_INTROSPECTION` | _removed_ | `environment` | Removed startup-environment fallback. Requires client auth on `/introspect`. In the supported PostgreSQL-backed runtime, `policy.requireClientAuthIntrospection` is authoritative. |
| `AEGAEON_REQUIRE_CLIENT_AUTH_INTROSPECT` | _removed_ | `environment` | Removed legacy alias. It is no longer read as a fallback; the supported runtime rejects this startup-managed policy variable when it is set. |
| `AEGAEON_REQUIRE_CLIENT_AUTH_REVOKE` | _removed_ | `environment` | Removed startup-environment fallback. Requires client auth on `/revoke`. In the supported PostgreSQL-backed runtime, `policy.requireClientAuthRevocation` is authoritative. |
