# Federated Broker / Downstream IdP Delivery Record

Last updated: 2026-04-27

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

This historical record captures the Phase B delivery for broker / federation management-plane
capabilities when Aegaeon has an **upstream authority** (for example, external OIDC or OpenID
Federation inputs) but also acts as an **IdP for downstream relying parties**. The current
implementation specification is `docs/specs/oidc-rp-brokering-spec.md`.

Compared with the primary-authority scenario, the runtime baseline was already much closer. The
main missing piece for this delivery track was not token issuance itself, but a first-class
**broker / federation control plane**.

This record does **not** widen the current released verification claim by itself.

Status note (2026-04-27): Phase B1-B7 is complete and was revalidated against the current source
trees on 2026-04-27. This document now serves as a delivery record and regression checklist for
the broker / federation control-plane posture.

## Current status

- Runtime supports upstream-login auto-provisioning, account-link creation, safe relink / conflict
  remediation, trust diagnostics, and broker logout-recovery handling.
- Management API already supports:
  - oauth profile CRUD
  - connection CRUD
  - federation configuration through configuration transactions
  - account-link search / link / unlink / relink / conflict resolution
  - trust-anchor, entity-cache, and trust-chain diagnostics operations
  - logout-recovery incident read / clear operations
  - downstream client CRUD
  - signing keys, key store, configuration versions
  - audit reads and export
- The generated management client and sibling admin console expose the same broker day-2 operator
  surfaces required for the delivered product posture.
- Revalidation on 2026-04-27 repaired two concrete regression-evidence issues without reopening
  the delivered scope:
  - the feature-gated server logout relay E2E fixture had drifted after `UpstreamAuthRequest`
    added `claim_release_policy`
  - the admin-console federation diagnostics tests now pin time explicitly so expiry-derived health
    assertions remain deterministic
- Fresh evidence recorded on 2026-04-27 includes:
  - server targeted regressions for federation configuration validation, JIT policy parsing,
    claim-release parsing, account-link safety gates, and upstream logout relay
  - the full sibling `@aegaeon/management-client` test suite
  - sibling admin-console broker / federation route tests covering JIT, attribute mapping, claim
    release, logout policy, account-link remediation, diagnostics, and logout recovery

Implication: the broker / federation control-plane gap described by this record is closed for the
current product posture. Follow-on work belongs in separate operational roadmaps, not in Phase B.

## Scope

### Phase B1 — First-class federation configuration

- Promote federation settings to first-class management resources instead of leaving them as
  partially implied runtime config.
- Minimum fields:
  - `upstreamIssuer`
  - `clientId`
  - `redirectUri`
  - `jwksCache`
  - `attributeMapping`
  - logout posture

Current status (2026-04-23):
- `configurationDocument.federation` is now validated on configuration-version create/activate for
  the current runtime shape:
  - `upstreamIssuer`
  - `clientId`
  - `redirectUri`
  - `jwksCache`
  - `attributeMapping`
  - `logout`
- Embedded secrets are explicitly rejected at this layer; operators must use keystore-backed
  references instead.
- Configuration transactions are the delivered federation-management surface for the current broker
  posture; a separate top-level federation resource is not required to satisfy the Phase B1 DoD.

Definition of done:
- federation settings are managed through config transactions
- admin console can inspect and update those settings

### Phase B2 — JIT provisioning policy

- Add explicit controls for upstream-driven provisioning:
  - enable / disable JIT create
  - domain allowlist
  - collision policy
  - initial status policy

Current status (2026-04-23):
- `configurationDocument.federation.jitProvisioning` is now validated on configuration-version
  create/activate.
- The upstream callback runtime now enforces:
  - explicit enable / disable
  - email-domain allowlist checks
  - verified-email policy for upstream email-driven JIT decisions (`requireVerifiedEmail`,
    default `true`)
  - collision policy (`rejectExistingEmail` / `reuseExistingEmail`)
  - initial local status (`ACTIVE` / `BLOCKED`)
- The configuration-edge `BLOCKED` operator input is normalized onto the local end-user
  `SUSPENDED` lifecycle state before downstream session issuance decisions are made.
- Linked or reused local users with effective `SUSPENDED` status are denied before downstream
  session issuance.
- If broker login lacks environment context while JIT policy is enabled, the callback fails closed.
- If a managed broker login has no explicit JIT policy and no existing account link, the callback
  fails closed instead of implicitly provisioning a local user.
- The admin console configuration-version editor now exposes
  `federation.upstreamIssuer`, `federation.clientId`, `federation.redirectUri`, and
  `federation.jitProvisioning` controls for:
  - enable / disable
  - domain allowlist
  - collision policy
  - initial local status
- The compose-backed stack E2E covers create/activate with those settings.

Definition of done:
- upstream federation login no longer implies implicit provisioning semantics
- operators can govern whether and how local user creation occurs

### Phase B3 — Attribute and claim mapping

- Add first-class mapping rules for upstream → local → downstream claims.
- Minimum capabilities:
  - source claim selection
  - transform / mapping rules
  - role / group mapping
  - downstream claim release policy

Current progress (2026-04-22):
- The admin console configuration-version editor now exposes
  `configurationDocument.federation.attributeMapping` as first-class form controls.
- Operators can add and remove mapping rows with:
  - `from`
  - `to`
  - optional `rule`
- The compose-backed stack E2E now covers create/activate flows that include upstream
  attribute-mapping entries.
- Configuration activation now emits a dedicated searchable audit event
  `management.federationAttributeMapping.changed.v1` whenever the normalized federation
  attribute-mapping rows change.
- The sibling admin console audit index now exposes a dedicated preset for that event type so
  operators can filter mapping-change history as a first-class broker operation.
- Brokered upstream callback handling now applies normalized attribute mappings at runtime:
  - supported targets currently include `email`, `email_verified`, `name` / `display_name`, and
    non-reserved custom claims
  - supported rules currently include direct copy, `lower`, and `mapGroups`
  - mapped values are synchronized into the local profile surface that downstream OIDC issuance and
    `userinfo` already consume
- The admin console configuration-version editor now exposes
  `configurationDocument.federation.claimRelease` as first-class form controls for
  broker-managed custom claims and their allowed downstream surfaces.
- Configuration create / activate validation now rejects malformed claim-release policies and
  unknown custom-claim targets before they can become active runtime state.
- Configuration activation now emits a dedicated searchable audit event
  `management.federationClaimRelease.changed.v1` whenever the normalized downstream claim-release
  policy changes.
- Team and environment audit pages now expose a dedicated preset for that event type so operators
  can filter claim-release history as a first-class broker operation.
- Brokered downstream issuance now enforces the normalized claim-release policy at runtime:
  - broker-managed custom claims can be independently allowed for `id_token` and `userinfo`
  - unmanaged custom claims preserve legacy downstream behaviour
  - blocked broker-managed custom claims remain stored in the local profile but are not released
    downstream
  - `userinfo` still requires `profile` scope before any custom claims are released
- Focused server tests cover policy parsing, configuration validation, audit normalization, ID Token
  filtering, and UserInfo filtering. Focused admin-console tests cover form round-tripping,
  configuration-editor document updates, and audit presets for claim-release changes.

Definition of done:
- downstream RP behaviour is configurable without patching server code
- mapping changes are auditable and versioned

### Phase B4 — Account-link management

- Add operator management over `account_links`.
- Required operations:
  - list
  - search by upstream issuer / subject
  - link
  - unlink
  - relink
  - conflict resolution

Current progress (2026-04-22):
- Management API now supports `list`, `search`, explicit `link`, conflict `preview/resolve`, `unlink`, `relink`, and bulk relink for account links.
- Search covers `upstreamIssuer`, `upstreamSubject`, `endUserSubject`, `endUserEmail`, and `connectionIdentifier`.
- `@aegaeon/management-client` exposes those operations.
- The admin console now has an `Account links` view under environment operations, explicit create controls, direct conflict resolution to a selected local user, relink guidance that narrows the view to the conflicting upstream subject, and bulk relink controls for selected links.
- The admin console now shows a bulk relink impact preview that summarizes selected links, moving
  versus already-assigned rows, distinct current local subjects, and stored upstream refresh-token
  exposure before the operator submits a merge-style relink.
- The conflict preview now surfaces operator guidance for single-link resolution decisions:
  - whether the current preview still requires manual review
  - whether the selected / recommended user is only an email match or not `ACTIVE`
  - whether the existing link stores an upstream refresh token that now requires explicit handling
    before reassignment
- Management API relink / conflict-resolution / bulk-relink flows now fail closed when a moved
  account link still stores an upstream refresh token unless the operator explicitly chooses one of:
  - `upstreamRefreshTokenHandling = clear`
  - `upstreamRefreshTokenHandling = retain`
- Management API conflict-resolution now also fails closed for low-confidence reassignment unless
  the operator explicitly chooses:
  - `lowConfidenceHandling = allow_low_confidence`
- Management API relink / conflict-resolution / bulk-relink now fail closed for non-`ACTIVE`
  target users unless the operator explicitly chooses:
  - `inactiveTargetHandling = allow_inactive`
- The admin console exposes the same handling choice inline for single-link relink, conflict
  resolution, and bulk relink, defaulting to `clear` while still allowing an explicit `retain`
  override.
- The admin console also exposes explicit operator acknowledgement for:
  - low-confidence conflict resolution
  - reassignment to a non-`ACTIVE` local user
- `@aegaeon/management-client` now serializes `upstreamRefreshTokenHandling`,
  `lowConfidenceHandling`, and `inactiveTargetHandling` for the relink / conflict / bulk
  endpoints and carries regression coverage for that request shape.
- The compose-backed stack E2E exercises create/conflict-preview/resolve/search/bulk-relink/unlink against seeded upstream links.
- Focused server/admin-console/SDK tests now cover the explicit override gates for:
  - stored upstream refresh tokens
  - low-confidence conflict resolution
  - reassignment to non-`ACTIVE` local users

Definition of done:
- account-link mistakes can be repaired through the management plane
- local identities and upstream identities can be reconciled safely

### Phase B5 — Federation and trust observability

- Add diagnostics over federation state:
  - trust-anchor inventory
  - resolved entity view
  - trust-chain cache view
  - manual refresh / evict
  - resolution failure diagnostics

Current progress (2026-04-22):
- Management API now supports trust-anchor inventory plus create/delete, entity-cache
  read/refresh/delete, and trust-chain read/refresh/delete.
- `@aegaeon/management-client` exposes those diagnostics and trust-anchor CRUD operations.
- The admin console diagnostics view now supports refresh/evict for entity-cache entries and trust
  chains, with fail-closed error surfacing when upstream fetch/chain resolution fails.
- The admin console diagnostics view now derives expiry-based health status for entity-cache and
  trust-chain entries, exposing summary counts and per-surface filters so operators can narrow the
  view to healthy or expired rows without leaving the page.
- Target-specific diagnostics route coverage now asserts both entity-cache and trust-chain refresh
  failures surface the affected entity plus request-id context, keeping operator-visible
  remediation breadcrumbs in the sibling admin console.
- Section-scoped diagnostics errors now keep entity-cache and trust-chain failures attached to the
  affected surface instead of collapsing them into a single page-wide banner, so operators can
  keep investigating adjacent surfaces without losing the failing target context.
- The compose-backed stack E2E seeds diagnostics rows and exercises read, fail-closed refresh, and
  evict for entity-cache entries and trust chains.

Definition of done:
- operators can diagnose trust or entity-cache issues without database inspection

### Phase B6 — Upstream / downstream session and logout policy

- Add management control over broker-session posture:
  - upstream logout propagation
  - back-channel posture
  - session hint binding
  - broken upstream session recovery

Current progress (2026-04-22):
- `configurationDocument.federation.logout` is validated on the server for:
  - `backChannel`
  - `sessionHintClaim`
  - `recoveryPolicy`
- The admin console configuration-version editor now exposes first-class controls for:
  - enable / disable management of `federation.logout`
  - upstream back-channel logout posture
  - optional session-hint claim binding
  - broken-session recovery policy (`force_prompt_login` / `disable_connection`)
- Focused admin-console tests cover helper-level JSON round-tripping and route-level configuration
  version creation with the logout posture present.
- The server runtime now parses `federation.logout` into the upstream connection/auth-request
  state, carries broker logout posture through successful upstream login, and stores upstream
  logout context on brokered auth sessions.
- `POST /auth/logout` now consumes that brokered logout context and performs front-channel upstream
  logout when:
  - the current auth session originated from upstream login
  - `backChannel` is `false`
  - upstream discovery advertises a valid `end_session_endpoint`
- RP-facing `/logout` now clears the local `aegaeon_auth_session` cookie whenever present.
- RP-facing `/logout` now reuses stored broker session context and performs front-channel upstream
  logout when:
  - the current auth session originated from upstream login
  - `backChannel` is `false`
  - upstream discovery advertises a valid `end_session_endpoint`
- When the RP request includes `post_logout_redirect_uri`, `/logout` now relays through the local
  `/oauth/upstream/logout/callback` endpoint with one-time state so the upstream front-channel
  logout completes before redirecting back to the RP.
- Operational note:
  - deployments that rely on this relay path must register
    `{base_url}/oauth/upstream/logout/callback` with the upstream OP when that OP validates
    `post_logout_redirect_uri`
- `sessionHintClaim` currently resolves selected string claims (`sid`, `sub`, `iss`, `acr`, plus
  string-valued additional claims) and maps the resolved value to upstream `logout_hint`.
- `recoveryPolicy` now defaults to `force_prompt_login` when omitted, is normalized into the
  federation logout audit snapshot, and is carried with broker logout context for follow-on
  recovery handling.
- Configuration activation now emits a dedicated searchable audit event
  (`management.federationLogoutPolicy.changed.v1`) when the normalized
  `configurationDocument.federation.logout` posture changes.
- Front-channel upstream logout relay now creates durable incident records in
  `aegaeon.federation_logout_recovery_incidents` instead of relying only on process-local memory.
- Relay callback handling now uses the durable incident record as the source of truth:
  - successful callbacks mark the incident `completed`
  - timed-out callbacks mark the incident `expired`
  - replays against already-resolved incidents emit
    `federation.upstreamLogoutRelay.callbackRejected.v1`
  - TTL-cache misses can still be recovered after a process restart when the durable record exists
- The same relay helper is now used by:
  - RP-facing `/logout` when `post_logout_redirect_uri` is present
  - local `POST /auth/logout` for upstream front-channel logout, with return to `/auth/login`
- `federation.upstreamLogoutRelay.started.v1`,
  `federation.upstreamLogoutRelay.completed.v1`, and
  `federation.upstreamLogoutRelay.expired.v1` are now emitted from the runtime path.
- `/oauth/upstream/:connection/authorize` now enforces active recovery incidents:
  - `force_prompt_login` adds upstream `prompt=login`
  - `disable_connection` fails closed with `temporarily_unavailable`
- The management plane now exposes durable recovery-incident operations:
  - environment-scoped incident listing with filters over `connectionId`, `status`, and
    `recoveryPolicy`
  - single-incident inspection
  - operator clear action with required reason and audit event
    `management.federationBrokenSession.cleared.v1`
- `@aegaeon/management-client` now exposes those durable recovery-incident operations for sibling
  control-plane consumers.
- The sibling admin console now completes the operator surface for this logout-recovery path:
  - incident list / filter / inspect / clear flows over the durable incident API
  - degraded / recovery-needed indicators on affected broker connections
  - direct navigation from the connection inventory and connection detail pages into remediation
  - audit visibility for runtime relay events and operator clear actions
- Focused admin-console tests cover the remediation flow and the new audit affordances.

Definition of done:
- downstream RP-facing logout semantics are explicit and auditable

### Phase B7 — Admin console completion

- Extend the sibling admin console with broker/federation operations:
  - federation settings UI
  - account-link UI
  - mapping editor
  - trust diagnostics UI

Current progress (2026-04-22):
- The sibling admin console now covers the main broker control-plane surfaces for:
  - federation settings / configuration versions
  - JIT provisioning controls
  - attribute mapping
  - downstream custom-claim release controls
  - account-link operations
  - trust diagnostics and cache actions
  - federation logout posture editing
  - broken-session recovery policy selection in the configuration editor
- durable federation logout recovery incident operations:
  - list / filter / inspect / clear
  - recovery-policy-aware remediation over the management API
  - degraded / recovery-needed indicators on affected broker connections
- Team and environment audit pages now expose broker logout and remediation events explicitly via:
  - a human-readable label in audit rows
  - preset filter affordances for federation attribute-mapping changes, downstream claim-release
    changes, federation logout posture changes, runtime relay events, and operator clear actions
  - route coverage in the admin-console test suite plus mock audit handlers for local/dev flows

Definition of done:
- broker/federation day-2 operations are possible from the admin console

## Sequencing

Recommended order:

1. B1 — federation configuration
2. B2 — JIT provisioning policy
3. B3 — attribute and claim mapping
4. B4 — account-link management
5. B5 — federation and trust observability
6. B6 — upstream/downstream session policy
7. B7 — admin-console completion

Rationale:
- configuration and provisioning policy define the control-plane contract first
- mapping and account-link operations are the next operational bottleneck
- diagnostics and session policy come after the main broker semantics are explicit

## Claim boundary note

- This roadmap strengthens broker/federation operability.
- It does not, by itself, change the current server-side claim wording.
- Any stronger claim requires separate evidence and wording updates.
