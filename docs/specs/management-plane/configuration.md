# Management Plane Configuration Model

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Issuer / domain policy (Phase 1)

### Canonical issuer

- Canonical issuer URL:
  - `issuerUrl = https://{environment}.{tenant}.{your-domain}`
  - no trailing slash (canonicalisation rule).
- Never derive `issuerUrl` or public endpoint URLs from the inbound request host.
- Routing is fail-closed:
  - if `Host` cannot be resolved to an Environment, return a 4xx (prefer `404` or `421`).

### Issuer immutability (Phase 1)

Issuer identity is fundamental to OIDC. Phase 1 treats issuer as immutable:

- `environments.issuerHost` and `environments.issuerUrl` are immutable after Environment creation.
- Attempts to change issuer must be rejected (recommend `409` with `ISSUER_IMMUTABLE`).
- To “change issuer”, create a new Environment and migrate clients/policies via a controlled
  procedure (environment clone tooling is allowed).

### DNS label constraints

`environment` and `tenant` must be valid DNS labels:

- lowercase `a-z`, digits `0-9`, and `-`
- length 1–63
- must start and end with an alphanumeric
- reject reserved labels that would collide with shared infrastructure (examples: `admin`, `api`,
  `console`, `www`, `static`, `root`, `assets`, `support`).

### Certificates

Phase 1 does not require full automation. The design assumes tenant-scoped wildcard certificates are
operationally realistic:

- `*.{tenant}.{your-domain}`

## Secure defaults (Phase 1)

- Authorization Code + PKCE (S256) required by default.
- Client Credentials enabled for M2M.
- Implicit and Resource Owner Password grant are disabled by default.
- Redirect URI registration:
  - exact match,
  - `https` required (allow `http://localhost` for local development only).
- DCR disabled by default and must be enabled per Environment.

### Client secret policy (Phase 1)

- Secrets are time-bound (`createdAt`, `expiresAt` UTC).
- Default expiry: 180 days.
- Maximum allowed expiry: 730 days (2 years).
- Concurrent active secrets:
  - default: 2 (primary + secondary),
  - optional policy extension: allow 3.
- Secondary secret grace period:
  - default: 30 days,
  - maximum: 90 days.
- Secrets must not be stored in plaintext.

### Token lifetimes (TTL granularity; Phase 1)

Phase 1 must not use a single ambiguous “token TTL”. Token lifetimes must be modelled explicitly:

- `accessTokenTimeToLiveSeconds`
- `idTokenTimeToLiveSeconds`
- `refreshTokenTimeToLiveSeconds`
- `authorizationCodeTimeToLiveSeconds`

Recommended defaults (policy guidance; not normative):

- access token: 3600
- id token: 3600
- refresh token: 2592000 (30 days)
- authorisation code: 300

### DPoP リプレイ検知（Redis 前提）

- Verified Core は DPoP 検証時に `replay_ticket`（JTI などの素材を含むチケット）を返すだけで、ストレージは担当しない。
- 制御プレーン/データプレーンは環境ごとの **名前空間 (namespace)** と TTL を決め、Redis 等の外部ストアに単一操作（`SET <key> 1 NX PX <ttl>`）で記録する。
- 推奨 TTL:
  - `AEGAEON_DPOP_IAT_WINDOW_SECS`（既存の受理窓＝5 分相当）＋ `AEGAEON_JWT_LEEWAY_SECS`（60 秒）を合算し、デフォルト 360 秒とする。
  - future skew（時計ズレ）を考慮した余裕を持たせる。
- キー素材:
  - 環境の namespace（例: `AEGAEON_DPOP_NAMESPACE` で明示。未設定時は issuer URL を使用）。
  - メソッド（大文字化された `htm`）、正規化済み URI (`htu`)、`jti`、公開鍵 thumbprint (`jkt`)、必要に応じて `ath`。
  - 上記を SHA-256 でハッシュし base64url で表現 → `dpop:v1:{namespace}:{hash}` を Redis キーとする。
- バックエンド実装要件:
  - `AEGAEON_DPOP_REDIS_URL` を必須とし、Redis を利用する。`noeviction`（明示的に eviction を禁止）設定を推奨。
  - Redis に接続できない／SET が失敗した場合は **fail-close**（`503 Temporarily Unavailable`, `error="temporarily_unavailable"`）としてクライアントに通知。
  - 旧来の未設定時インメモリ実装は protocol-level test harness 専用の名残であり、server runtime の supported configuration からは廃止する。
  - 同一キーが既に存在した場合は replay と判定し、`invalid_token`（DPoP replay）で拒否。
- 監査:
  - 成功・再試行・障害（バックエンド unavailable）それぞれを audit event として記録できるようにする。

## Environment configuration

### Snapshot model (source of truth)

Environment-scoped “data plane configuration” is represented as a single configuration document
(snapshot). It includes:

- issuer host / canonical issuer URL,
- JWKS and signing key state (active/next/retiring/revoked),
- policy toggles (PKCE, DCR, sender constraints, algorithm allowlists, TTLs),
- scope allowlists,
- client registry (metadata required by the data plane),
- rate limiting settings (Phase 1 minimal),
- connections (external IdP configuration “container”; expanded in Phase 2+).

### Configuration scopes (Phase 1; normative)

The management plane separates configuration into two scopes:

- **System (process-global)**: deployment/operator configuration such as database connectivity,
  reverse-proxy trust, JWKS fetcher tuning, logging, and other host-level settings. These MUST NOT
  be stored in Environment configuration snapshots and MUST NOT be tenant-admin configurable.
- **Environment (issuer-scoped)**: data plane behaviour that can vary by issuer and must be
  versioned/rolled back safely (policy toggles, signing keys, client registry, TTLs, etc.). These
  MUST be stored in Environment configuration snapshots (`configuration_versions`) and updated only
  via Configuration Transactions.

### Environment-variable split (Phase 1; guidance)

Phase 1 introduces a clear split between:

- **System env vars (operator-controlled, process-global)**: affect server infrastructure and
  security caps; not versioned per issuer.
- **Environment configuration (DB-backed, issuer-scoped)**: versioned, rollbackable, and mutated
  only via configuration transactions.

Migration guidance (non-exhaustive; names reflect current code):

- Move to DB (stored in `configurationDocument.policy` / `environment_policies` and applied per
  Environment):
  - `AEGAEON_REQUIRE_STATE` → `policy.requireStateParameter`
  - `AEGAEON_STRICT_AUTHORIZE_REDIRECT` → `policy.strictAuthorizeRedirect`
  - `AEG_REQUIRE_CLIENT_AUTH_*` → `policy.requireClientAuth*`
  - `AEG_DPOP_*` → `policy.dpop*`
  - `AEGAEON_PAR_EXPIRES_IN` → `policy.parExpiresInSeconds`
  - `AEGAEON_REQUEST_OBJECT_JTI_TTL` → `policy.requestObjectJtiTtlSeconds`
  - `AEGAEON_ENABLE_PRIVATE_KEY_JWT` → `policy.privateKeyJwtEnabled`
  - `AEGAEON_CLIENT_JWT_ALLOWED_ALGS` / `AEGAEON_CLIENT_JWT_REQUIRE_KID` → `policy.clientJwt*`
  - `AEGAEON_PKJWT_JTI_WINDOW_SECS` / `AEGAEON_JWT_LEEWAY_SECS` → `policy.pkjwtJtiWindowSeconds` /
    `policy.jwtLeewaySeconds`
  - `AEG_DCR_REQUIRE_*` / `AEGAEON_DCR_ALLOWED_SENDER_METHODS` → `policy.dcr*`
  - `AEG_SSA_*` → `policy.ssa*`
  - `AEG_OIDC_*` feature toggles → `policy.oidc*` (issuer identity is derived from the Environment)
  - `AEG_MTLS_*` → `policy.mtls*`

- Remain env (system scope; not stored per Environment):
  - Database bootstrap: `AEGAEON_DATABASE_URL`, `AEGAEON_DB_MAX_CONNECTIONS`,
    `AEGAEON_DB_ACQUIRE_TIMEOUT_SECS`. PostgreSQL is required; `DATABASE_URL` is not a server
    runtime fallback. `AEGAEON_DB_ENABLED` was removed and any configured value fails closed.
  - Runtime environment selection: `AEGAEON_RUNTIME_ISSUER_HOST` selects the active
    management-database Environment by canonical `issuer_host`. Public issuer URL authority remains
    in PostgreSQL.
  - Transport/proxy trust: `AEGAEON_TRUSTED_PROXIES`, `AEGAEON_REQUIRE_TLS_PROXY`,
    `AEGAEON_ALLOW_PROXY_CHAIN_LENGTH`, `AEGAEON_REQUIRE_MTLS_FROM_PROXY`, `AEGAEON_FORWARD_HEADER_LOG_VALUES`
  - JWKS fetcher tuning (global): `AEG_JWKS_*`
  - Global security posture caps: `AEG_POLICY_*`
  - Verified-parser feature flags: `AEGAEON_REQUEST_OBJECT_EVERPARSE_RUNTIME`,
    `AEGAEON_DCR_EVERPARSE_RUNTIME`
  - Management plane integration: management Origin allowlist and issuer base-domain defaults are
    authoritative in `aegaeon.control_plane_policies`; management cookies are always Secure and
    `AEGAEON_MANAGEMENT_COOKIE_SECURE` is rejected if present.
  - Dev/test helpers: `AEG_TEST_CLIENT_*`. Main-server metrics exposure was removed; operational
    metrics are served by the authenticated management endpoint.

### Snapshot schema (schemaVersion = 1; Phase 1; normative)

In Phase 1, `configuration_versions.configurationDocument` uses `schemaVersion = 1` and MUST be a
JSON object with the following top-level keys (all JSON keys use `camelCase`):

- `schemaVersion` (number; MUST be `1`)
- `issuerHost` (string; DNS host)
- `issuerUrl` (string; MUST be `https://{issuerHost}` with no trailing slash)
- `policy` (object; policy document used by the data plane)
- `scopeAllowlist` (array of strings)
- `clients` (array; client registry entries required by the data plane)
- `signingKeys` (array; signing key metadata and public JWKS material)
- `keyStore` (object; keystore configuration reference / redacted public view)
- `rateLimit` (object, optional; Phase 1 minimal)
- `connections` (object, optional; reserved for Phase 2+)

Canonicalisation rules (MUST):

- Control-plane writers MUST serialise `configurationDocument` with deterministic ordering (sorted
  object keys, UTF-8, no insignificant whitespace) so `configurationHash` comparisons are stable
  across services.
- Arrays MUST use deterministic ordering. In particular, `clients` SHOULD be sorted by
  `clientIdentifier`, `signingKeys` by `kid`, and allowlists alphabetically.
- Consumers MUST reject snapshots with unknown `schemaVersion` values and MUST ignore unknown keys to
  preserve forward compatibility.

Secret material rules (MUST):

- The snapshot MUST NOT contain any plaintext client secrets or keystore credentials/tokens.
- Any secret material MUST be stored separately (encrypted) and referenced by identifiers, or
  treated as write-only input that is never returned by read endpoints.

#### Policy document (schemaVersion = 1; Phase 1; normative)

`configurationDocument.policy` MUST be a JSON object with the following keys:

- `pkceRequired` (boolean)
- `dcrEnabled` (boolean)
- `requireStateParameter` (boolean)
- `strictAuthorizeRedirect` (boolean)
- `requireClientAuthToken` (boolean)
- `requireClientAuthPar` (boolean)
- `requireClientAuthIntrospection` (boolean)
- `requireClientAuthRevocation` (boolean)
- `dpopStrict` (boolean)
- `dpopIatWindowSeconds` (number)
- `parExpiresInSeconds` (number)
- `privateKeyJwtEnabled` (boolean)
- `clientJwtAllowedAlgs` (array of strings)
- `clientJwtRequireKid` (boolean)
- `jwtLeewaySeconds` (number)
- `pkjwtJtiWindowSeconds` (number)
- `requestObjectJtiTtlSeconds` (number)
- `dcrRequirePkceForPublic` (boolean)
- `dcrRequirePkceForConfidential` (boolean)
- `dcrRequireSenderConstrained` (boolean)
- `dcrAllowedSenderMethods` (array of strings)
- `ssaJwtPem` (string, optional; RSA public key PEM used to verify DCR software statements)
- `ssaExpectedIss` (string, optional)
- `ssaExpectedAud` (string, optional)
- `ssaLeewaySeconds` (number)
- `oidcEnabled` (boolean)
- `oidcEnableDiscovery` (boolean)
- `oidcEnableUserinfo` (boolean)
- `oidcEnableLogout` (boolean)
- `oidcEnableBackchannelLogout` (boolean)
- `oidcLogoutSessionTtlSeconds` (number)
- `oidcBackchannelLogoutTimeoutSeconds` (number)
- `oidcRequireNonce` (boolean)
- `mtlsEnabled` (boolean; when true, discovery documents include RFC 8705 mTLS metadata)
- `mtlsBaseUrl` (string, optional; defaults to `issuerUrl` when omitted)
- `mtlsAliasParEnabled` (boolean; non-standard alias toggle)
- `allowedSigningAlgorithms` (array of strings)
- `allowedGrantTypes` (array of strings)
- `accessTokenTimeToLiveSeconds` (number)
- `idTokenTimeToLiveSeconds` (number)
- `refreshTokenTimeToLiveSeconds` (number)
- `authorizationCodeTimeToLiveSeconds` (number)

Example (abridged):

```json
{
  "schemaVersion": 1,
  "issuerHost": "prod.acme.apne1.aegaeon.cloud",
  "issuerUrl": "https://prod.acme.apne1.aegaeon.cloud",
  "policy": {
    "pkceRequired": true,
    "dcrEnabled": false,
    "requireStateParameter": true,
    "strictAuthorizeRedirect": true,
    "requireClientAuthToken": true,
    "requireClientAuthPar": true,
    "requireClientAuthIntrospection": true,
    "requireClientAuthRevocation": true,
    "dpopStrict": true,
    "dpopIatWindowSeconds": 300,
    "privateKeyJwtEnabled": false,
    "clientJwtAllowedAlgs": ["RS256"],
    "clientJwtRequireKid": false,
    "jwtLeewaySeconds": 60,
    "pkjwtJtiWindowSeconds": 300,
    "requestObjectJtiTtlSeconds": 600,
    "parExpiresInSeconds": 90,
    "dcrRequirePkceForPublic": false,
    "dcrRequirePkceForConfidential": false,
    "dcrRequireSenderConstrained": false,
    "dcrAllowedSenderMethods": ["dpop"],
    "ssaLeewaySeconds": 120,
    "oidcEnabled": false,
    "oidcEnableDiscovery": true,
    "oidcEnableUserinfo": true,
    "oidcEnableLogout": false,
    "oidcEnableBackchannelLogout": false,
    "oidcLogoutSessionTtlSeconds": 600,
    "oidcBackchannelLogoutTimeoutSeconds": 2,
    "oidcRequireNonce": false,
    "mtlsEnabled": false,
    "mtlsAliasParEnabled": false,
    "allowedSigningAlgorithms": ["RS256", "EdDSA"],
    "allowedGrantTypes": ["authorization_code", "refresh_token"],
    "accessTokenTimeToLiveSeconds": 3600,
    "idTokenTimeToLiveSeconds": 3600,
    "refreshTokenTimeToLiveSeconds": 2592000,
    "authorizationCodeTimeToLiveSeconds": 300
  },
  "scopeAllowlist": ["openid", "profile"],
  "clients": [],
  "signingKeys": [],
  "keyStore": { "type": "databaseEncrypted", "configuration": {}, "redacted": true }
}
```

### Source of truth and projections (Phase 1; normative)

Conclusion:

- The source of truth for an Environment is the immutable snapshot in `configuration_versions`.
- Normalised tables (`clients`, `client_secrets`, `signing_keys`, `environment_policies`, etc.) are
  projections/indexes for querying and constraints. They must always match the active snapshot.

Invariants (MUST hold):

- `environments.activeConfigurationVersionId` identifies the unique active snapshot (“Active
  Snapshot”) for the Environment.
- Projection tables MUST match the Active Snapshot.
- The data plane MUST NOT read from projection tables. It must read the Active Snapshot (or a
  derived distribution bundle) only.

Write procedure (Configuration Transaction; MUST be atomic):

1. Read the Active Snapshot.
2. Apply the requested change to produce a new snapshot.
3. Validate the new snapshot.
4. Persist the new snapshot in `configuration_versions` (immutable).
5. Update `environments.activeConfigurationVersionId` to the new version.
6. Update projection tables to match the new snapshot.
7. Emit audit events.

## Configuration versioning and rollback (Phase 1)

- Source of truth is an immutable configuration snapshot stored per Environment.
- `environments.activeConfigurationVersionId` points to the active snapshot.
- Optional (recommended) review aid:
  - store a JSON Patch (RFC 6902) between versions.

Activation and rollback:

- Activation sets a specific version as active and emits an audit event.
- Rollback activates an older version and emits an audit event.

### Rollback safety: irreversible operations (Phase 1; normative)

Rollback must not resurrect revoked credentials. Phase 1 enforces irreversibility for revocation:

- Revoked signing keys and revoked client secrets MUST NOT become usable again due to activation or
  rollback.

To enforce this, Phase 1 introduces an Environment-scoped monotonic security ledger:

- `revokedSigningKeyIds`: set of revoked signing key IDs.
- `revokedClientSecretIds`: set of revoked client secret IDs.

Activation validation (MUST):

- When activating (including rollback), if the target snapshot would make any ledger-revoked key or
  secret usable (e.g. `ACTIVE/NEXT/RETIRING` for keys or an active secret slot), the server MUST
  reject activation with `409` (recommend `SECURITY_LEDGER_CONFLICT`).

#### Revocation ledger design

- Ledger tables (`environment_revoked_signing_keys`, `environment_revoked_client_secrets`) MUST
  enforce uniqueness on `(environment_id, identifier)` and MUST NOT expose delete/update paths.
- Configuration activation MUST consult the ledger; if the snapshot references a revoked identifier,
  the server rejects with `409 SECURITY_LEDGER_CONFLICT`.
- Client secret revocations MUST append to the ledger within the same transaction as the
  configuration snapshot so concurrent activations observe the revocation.
- Ledger tables SHOULD record `revoked_at` and `revoked_by_administrator_id` for auditability and
  SHOULD expose an index on `revoked_at` to support TTL/retention jobs.

### Security downgrade gating (Phase 1; normative)

Security downgrades require explicit intent and stronger operator gates. Downgrades include (minimum
set):

- disabling PKCE requirements,
- enabling or loosening DCR,
- enabling additional grant/response types (especially implicit/ROPC),
- widening signing algorithm allowlists,
- materially increasing token lifetimes.

Phase 1 requirements:

- Downgrade activations (including rollback) MUST require explicit intent:
  - the activation request must include `allowSecurityDowngrade = true`,
  - and MUST include a human-readable `reason` stored in audit logs.
- Downgrade activation SHOULD be restricted to privileged roles (Owner/Administrator) and MFA-gated
  in SaaS/Enterprise deployments.

Data plane fetch policy:

- Recommended: continue serving last-known-good configuration on fetch failures and emit alerts.
- Alternative: fail-closed (deployment policy choice).
