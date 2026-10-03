# Management Plane Configuration Model

Last updated: 2026-09-15

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Timestamp representation

OAuth profile `createdAt`, `updatedAt` and present `expiresAt` values, and client
secret `createdAt` and `expiresAt` values, use RFC 3339 UTC timestamps
with millisecond precision, such as `2030-01-01T00:00:00.123Z`. The `T` and `Z`
are literal characters in the value, without surrounding quotation marks.
For OAuth profiles, an absent optional `expiresAt` field means that no expiry
is set. Client secrets require an expiry.

OAuth profile page tokens are opaque. Their timestamp component preserves
PostgreSQL microseconds and pairs the timestamp with the row UUID so that
pagination does not skip or repeat profiles created within one millisecond.
Clients should return the supplied page token unchanged. Tokens issued with
malformed timestamps by older versions must be discarded; restart the list
without a page token. This correction does not require a database migration.

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

Rust FFI は DPoP の署名・freshness 等を検査して `jti` と任意の nonce を返します。
リプレイ記録と nonce policy は Rust middleware の責務です。FFI が replay ticket を
発行して保存まで保証するものではありません。

- 名前空間は management database の Environment ID から導出します。issuer URL や
  `AEGAEON_DPOP_NAMESPACE` による上書きは使いません。
- リプレイキーの素材は、長さ付きで連結した `jkt` と `jti` です。これと environment
  namespace を長さ付きで連結して SHA-256 / base64url で表現し、environment / surface
  ごとの Redis prefix と組み合わせます。`htm`、`htu`、`ath` はこのキー素材に含めません。
- middleware は保存直前に TTL を
  `max(2 * MAX_DPOP_IAT_WINDOW_SECS + 1, 2 * iat_window_secs + 1, caller TTL)`
  秒へ引き上げます。現在の supported maximum による下限は **601 秒**です。
  より長い caller TTL は維持し、算術 overflow は fail-closed にします。
- `iat` window は active configuration document の `policy.dpopIatWindowSeconds`
  が定めます。整数秒で包含する未来側の端から最終受理秒までを覆うため、片側の
  window と JWT leeway の加算では足りません。JWT leeway は DPoP freshness に加算しません。
- nonce enforcement の有効・無効によらず同じ TTL 下限を適用します。nonce TTL へ
  短縮せず、nonce 自体が一回限りとは仮定しません。
- server runtime は `AEGAEON_DPOP_REDIS_URL` による共有 Redis を必須とし、
  `SET <key> 1 NX PX <ttl_ms>` で原子的に保存します。既存キーは replay として拒否し、
  接続・保存失敗は `503` / `temporarily_unavailable` として fail-closed にします。
  インメモリ実装は直接 unit test / fuzz / protocol harness 用です。

容量増加、共有ストアの no-eviction・時計前提、および旧 instance の最終受理から
必要な期間 admission を停止して待つ更新手順は、
[DPoP リプレイストア運用ガイド](../../operations/dpop-replay-store.md)に従います。
既存の短い記録を新 instance から復元することはできません。

## Environment configuration

### Document state and independently managed objects

The versioned configuration document contains the issuer host/canonical URL,
policy toggles and TTLs, scope allowlist, key-store configuration and federation
settings. Client metadata, OAuth profiles, connections, runtime keys and client
secrets live in independently managed database rows. They are not historical
object snapshots embedded in `configuration_versions`.

The [activation contract](#current-persistence-and-activation-contract) defines
which current memberships move with a document version and which credential
version IDs retain provenance.

### Configuration scopes (Phase 1; normative)

The management plane separates configuration into two scopes:

- **System (process-global)**: deployment/operator configuration such as database connectivity,
  reverse-proxy trust, JWKS fetcher tuning, logging, and other host-level settings. These MUST NOT
  be stored in Environment configuration snapshots and MUST NOT be tenant-admin configurable.
- **Environment (issuer-scoped)**: policy and scope/key-store configuration are
  stored in `configuration_versions` and its document-state tables. Independently
  managed clients, profiles, connections and credentials also belong to an issuer,
  but are not restored from document history. Their mutations use the applicable
  management/runtime transaction and lifecycle rules.

### Environment-variable split (Phase 1; guidance)

Phase 1 introduces a clear split between:

- **System env vars (operator-controlled, process-global)**: affect server infrastructure and
  security caps; not versioned per issuer.
- **Environment configuration (DB-backed, issuer-scoped)**: document state is versioned;
  independent objects follow their own transaction and lifecycle rules.

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

- `clientCredentials` (object; optional on historical documents, defaults to deny-all version 1;
  see [client-credentials target authorization](../../configurations/client-credentials.md)
  for caller/target rules, defaults and independent resource-server introspection bindings)
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
  "keyStore": { "type": "databaseEncrypted", "configuration": {}, "redacted": true }
}
```

### Current persistence and activation contract

The immutable configuration document stores policy, scope allowlist, key-store
configuration and federation settings. It does not contain client, profile,
connection, runtime-key or client-secret snapshots. These objects are managed
independently in their stable-ID database rows; runtime readers use the database.

Policy PATCH and explicit activation MUST hold the environment row lock and
commit the following changes together:

1. Validate and persist the selected configuration document and its policy,
   scope-allowlist and key-store state.
2. Transfer current-version ACTIVE clients and profiles, and ACTIVE or DISABLED
   connections, to the selected version. Preserve every other field, including
   profile expiry, connection status, object identity and credential bindings.
3. Archive the previous version, activate the selected version, update the
   environment pointer and write the audit events.

The transfer source is the current version read from the locked environment,
including when activating a draft based on an older version. Historical and
unrelated-environment rows MUST NOT be imported. Deleted/retired objects remain
unchanged. An unexpected live membership already in the destination rejects the
transition with `409 configuration_membership_conflict`. Re-activating the current
version does not transfer memberships.

Runtime-key and client-secret version IDs record provenance. Their runtime
selection depends on environment, identity and lifecycle/expiry, rather than
active-version equality. Activation MUST preserve that provenance and MUST NOT
restore revoked or expired credentials.

## Configuration versioning and recovery

`environments.activeConfigurationVersionId` selects the active document. A
successful activation changes the document and effective memberships atomically;
an aborted transaction leaves the committed state unchanged. If the COMMIT
acknowledgement is lost, the outcome is unknown and must be reconciled before
retrying. Concurrent writers
must derive the active version from the locked environment, including after a
lock wait.

This is not complete restoration of a historical environment snapshot. Archived
versions are not directly reactivated by the current API. Reverting document
settings requires a validated new draft and the existing security-downgrade and
revocation checks; it does not restore historical clients or credentials.

An environment already damaged by an earlier incomplete activation needs an
explicitly audited recovery based on its known prior membership set. A later
activation must not automatically collect every historical row in that environment.
Use the [configuration membership recovery runbook](../../operations/configuration-membership-recovery.md)
for an approved row set, rollback-only rehearsal, atomic audit and post-recovery
checks. Runtime fingerprints require PostgreSQL 11 or newer
(`pg_catalog.sha256(bytea)`).

### Rollback safety: irreversible operations

Activation MUST NOT make revoked keys, revoked secrets or expired credentials
usable again. The current implementation preserves the independently managed
credential rows, their version provenance and their lifecycle/expiry fields.
Runtime readers continue to enforce those fields after a configuration change.

The schema also contains legacy revocation-ledger tables. The compatibility
activation guard can reject revoked IDs in a legacy `clientSecrets` document;
this is not a claim that the current strict document format contains credential
snapshots, or that every ledger is consulted by every activation path.

Complete historical snapshot restoration is not implemented. Any future support
must separately specify and validate monotonic revocation checks for all restored
credential types; it must not infer safety from the presence of ledger tables.

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
