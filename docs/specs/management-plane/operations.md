# Management Plane Operations

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Signing keys and keystores

### Signing key states

- `ACTIVE` (currently used for signing)
- `NEXT` (next to be activated)
- `RETIRING` (kept for verification compatibility)
- `REVOKED` (incident response)

Constraints (recommended for operability):

- exactly one `ACTIVE` per Environment,
- at most one `NEXT` per Environment.

### Rotation procedure (Phase 1)

- Create `NEXT`
- Create and activate a configuration version (JWKS includes both)
- Activate (switch signing to `ACTIVE = NEXT`, old `ACTIVE -> RETIRING`)
- Remove/disable retiring keys after a retention window

### JWKS canonical path (Phase 1)

To avoid ambiguity, Phase 1 fixes a canonical JWKS path:

- canonical: `https://{issuerHost}/.well-known/jwks.json`
- OIDC discovery `jwks_uri` MUST point to the canonical path.

Additional aliases may be provided for compatibility, but the canonical path above is normative.

### Keystore plugin interface (Phase 1 contract)

Even if Phase 1 ships with a local DB backend only, the interface must support “keys never leave the
HSM/KMS” backends.

Provider:

- `initialize(configuration) -> KeyStore`
- `capabilities() -> { algorithms, supportsDeletion, supportsRotation, supportsExportPublicJwk }`

Key store:

- `createKey(algorithm, metadata) -> KeyReference` (includes `kid`)
- `getPublicJwk(keyReference) -> Jwk`
- `listKeys(filter) -> [KeyMetadata]`
- `setKeyStatus(keyReference, status)`
- `deleteKey(keyReference)` (optional)
- `healthCheck() -> ok | error`

Signer:

- `signJws(keyReference, algorithm, signingInputBytes) -> signatureBytes`
  - must return JOSE/JWS-compatible signature bytes (normalised format).

### Secret and keystore disclosure policy (Phase 1; normative)

Client secrets:

- List/read APIs MUST return metadata only (no secret value).
- Secret value must be returned exactly once at issuance/rotation time.

Keystore configuration:

- `GET .../keyStores/current` MUST return a redacted public view.
- Any credentials/tokens/secret material must be treated as write-only input and MUST NOT be
  returned by read endpoints.

## Client management (Phase 1)

Client types:

- Web (confidential)
- Machine-to-machine (confidential)
- SPA / Native are allowed but should be strongly constrained (Phase 2+ hardening).

Client metadata (representative):

- `redirectUris`
- `allowedGrantTypes`
- `allowedScopes`
- `tokenEndpointAuthenticationMethod` (default `client_secret_basic`)
- `requirePkce`

## User operations (Phase 1 minimal)

Phase 1 focuses on operational actions, not full user CRUD:

- search (subject/email),
- block/unblock,
- invalidate sessions,
- revoke refresh tokens,
- search recent authentication events (optional).

## Audit logging (Phase 1)

Audit is mandatory for all control-plane operations.

Canonical internal payload (draft):

- `eventType`
- `category` (`management` / `security` / `dataPlane`)
- `outcome` (`success` / `failure`)
- `severity` (`info` / `warn` / `error`)
- `actor` (administrator/system + ip + userAgent + mfa)
- `target` (type/id)
- `request` (`requestId`, optional `traceId`/`spanId`)
- `change` (when applicable: from/to configuration version, JSON Patch)
- `data` (free-form)

Audit records MUST carry `teamId`, `tenantId`, and `environmentId` (when applicable) to keep queries
scoped fail-closed. They MUST also record authentication context (for example, `authMethod`,
`mfaUsed`, and API key id/capabilities when relevant) and correlation identifiers so investigations
can join audit trails with request logs and traces.

### Event type naming (Phase 1)

Phase 1 fixes event type naming with explicit version suffixes to preserve compatibility:

- management plane: `management.<resource>.<action>.v1`
- data plane security events: `dataPlane.<category>.<action>.v1`

Examples (minimum Phase 1 set):

- Authentication lifecycle:
  - `management.authentication.login.succeeded.v1`
  - `management.authentication.login.failed.v1`
  - `management.authentication.logout.v1`
  - `management.authentication.session.terminated.v1`
- Hierarchy lifecycle:
  - `management.team.created.v1`
  - `management.team.updated.v1`
  - `management.team.deleted.v1`
  - `management.tenant.created.v1`
  - `management.tenant.updated.v1`
  - `management.tenant.deleted.v1`
  - `management.environment.created.v1`
  - `management.environment.updated.v1`
  - `management.environment.deleted.v1`
- Configuration lifecycle:
  - `management.environment.configurationVersion.created.v1`
  - `management.environment.configurationVersion.activated.v1`
  - `management.environment.configurationVersion.archived.v1`
  - `management.environment.policy.updated.v1`
- Client registry:
  - `management.client.created.v1`
  - `management.client.updated.v1`
  - `management.client.deleted.v1`
  - `management.clientSecret.issued.v1`
  - `management.clientSecret.revoked.v1`
  - `management.clientSecret.revokedAll.v1`
- OAuth profiles:
  - `management.oauthProfile.created.v1`
  - `management.oauthProfile.updated.v1`
  - `management.oauthProfile.deleted.v1`
  - `management.oauthProfile.assigned.v1`
  - `management.oauthProfile.unassigned.v1`
- Key and keystore:
  - `management.signingKey.rotated.v1`
  - `management.signingKey.activated.v1`
  - `management.signingKey.revoked.v1`
  - `management.keyStore.updated.v1`
- Audit export:
  - `management.auditExport.configured.v1`
  - `management.auditExport.triggered.v1`

Custom deployments MAY append additional event types using their own namespace (e.g.
`custom.*.v1`) but MUST NOT reuse the reserved identifiers above for different semantics.

### Storage strategy (Phase 1)

Control-plane audit events MUST be stored in the control-plane RDBMS (`audit_events`). This enables
transactional consistency: the audit event is committed in the same database transaction as the
mutating operation (for example: configuration activation, client secret rotation, signing key
revocation).

Data-plane telemetry has different volume and retention characteristics:

- Request/response access logs and high-frequency runtime events SHOULD be shipped as structured
  logs/metrics/traces to the operator’s observability pipeline (OTel → log store/SIEM) and MUST NOT
  rely on the RDBMS as a full-fidelity log sink.
- Security-relevant data-plane events MAY also be duplicated into `audit_events` under
  `category = dataPlane` when (and only when) the expected volume is bounded and the operator needs
  a single query surface for investigations.

For long-term retention and tamper-evidence, deployments SHOULD export audit events from the RDBMS
to append-only storage (for example: S3 NDJSON) and enable immutability controls where available
(Object Lock / WORM). Prefer an outbox/CDC-style export to avoid losing events during failures.

Export:

- SaaS Phase 1: S3 export (NDJSON recommended).
- Phase 2+: CloudEvents envelope and OCSF mapping.

Storage:

- Partition `audit_events` by month on `occurred_at`.
- Index `(environment_id, occurred_at)` and Team-scoped queries.
- Retention:
  - SaaS default 90 days (configurable),
  - OSS: operator responsibility.

## Observability (Phase 1)

- Metrics per Environment/issuer (token issuance counts, reject counts, latency, 5xx, 429).
- Request correlation:
  - `requestId` required across logs and audit,
  - optionally store trace identifiers.

## Rate limiting and abuse controls (Phase 1)

- Environment-scoped `rateLimit` configuration.
- Simple limits are acceptable initially (IP/client-based).
- Rejections should be recorded as security/audit events.
