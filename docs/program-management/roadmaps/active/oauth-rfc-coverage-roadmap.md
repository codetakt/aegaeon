# OAuth RFC Coverage Roadmap (AS/OP + OAuth Client)

Last updated: 2026-03-08

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This roadmap expands Aegaeon’s OAuth feature coverage towards “complete” support of the **current
OAuth WG RFC set** (plus the OAuth 2.1 draft) across two roles:

- **AS/OP**: OAuth Authorization Server / (optionally) OpenID Provider for downstream applications.
- **OAuth Client**: OAuth Client (and, where applicable, OIDC RP) to upstream identity systems (SoT).

OIDC federation requirements are tracked separately in the OIDC workstreams described by
`docs/program-management/roadmaps/active/current-execution-plan.md` (and the historical record at
`docs/program-management/historical/roadmaps/oidc-execution-plan.md`), but several OAuth RFCs below are
prerequisites for robust federation (client authentication, mTLS, issuer binding).

## Assumptions (explicit)

1. **Multiple upstream IdPs** are supported (federation/brokering use cases).
2. **SAML is out of scope** for this roadmap (handled by a separate facade component).
3. **Standards-first, fail-closed defaults** (no implicit/ROPC by default; strong PKCE + sender constraints).
4. **Strong audit baseline** for security outcomes: if the audit sink write fails, the operation fails.
   - Policy: `docs/policies/audit-policy.md`
5. The authoritative status tracker remains `spec/compliance-matrix.yaml` (no shadow lists).
6. OIDC-mandated `RS256` verification-boundary work is tracked separately in the OIDC roadmaps so this OAuth roadmap can keep broad RSA in compat by default.

## Definition of “supported”

For each RFC, we use the following levels:

- **Verified**: requirements tracked in `spec/compliance-matrix.yaml` with tests/proofs and referenced artefacts.
- **Implemented (untracked)**: code exists, but not yet represented and evidenced in the compliance matrix.
- **Planned**: not implemented yet (no claim).
- **Docs-only**: RFC does not require protocol surface changes; we document the posture and enforce key properties.

## Current snapshot (gap analysis)

- **Verified (tracked)**: RFC 6749/6750/7009/7591/7592/7636/7662/7800/8414/8628/8693/8705/8707/8725/9068/9101/9126/9207/9278/9396/9449/9470/9700/9701/9728/9901
  and JOSE (RFC 7515–7519).
- **Verified (tracking-only / doc-only)**: RFC 8252 (Native Apps posture) is documented with explicit
  non-implementation notes.
- **Not applicable**: RFC 7522 (SAML assertion profile) is `not_applicable` because SAML is terminated by an
  external facade (see `docs/policies/saml-facade-policy.md`).
- **Partial**: global-002 (the strong-constraint claim currently applies to the verified allowlist and verified parsing/FFI paths only; broader interoperability surfaces still rely on compat crypto. OIDC-mandated `RS256` closure is tracked separately in the OIDC roadmaps).
- **Verified**: OIDC-1-009 (OIDC RP upstream token refresh — F\* `UpstreamRefresh.fst` with 17 lemmas,
  e2e tests with mock IdP, promoted to `verified` in Phase 7).
- **Tracking / doc-only**: RFC 6755 (OAuth Privacy Considerations), RFC 6819 (OAuth Threat Model),
  RFC 8176 (Authentication Method Reference Values), RFC 9123 (OAuth 2.0 for Browser-Based Apps)
  — informational/BCP RFCs with no protocol surface; tracked for posture alignment.

## RFC 7592 — implemented (Phase 8b)

RFC 7592 (Dynamic Client Registration Management) is now fully implemented on the public `/register` endpoint:
- **GET /register/{client_id}**: Client Configuration Read (authenticated via `registration_access_token`)
- **PUT /register/{client_id}**: Client Configuration Update (validates metadata, rotates token)
- **DELETE /register/{client_id}**: Client Configuration Delete (returns 204, deregisters from PAR)
- POST /register (RFC 7591) response enhanced with `registration_access_token`, `registration_client_uri`, `client_id_issued_at`
- F\* spec: `fstar/dcr/DcrManagement.fst` (5 lemmas, 0 admit)
- 10 integration tests in `dcr_management_test.rs`

## RFC 9068 — implemented (Phase 8b)

RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens) is now fully implemented as opt-in (`AEGAEON_ENABLE_JWT_ACCESS_TOKENS`):
- JWT ATs use `typ: at+jwt` header, contain required claims (iss/sub/aud/client_id/iat/exp/jti/scope)
- `cnf` claim with `jkt` binding for sender-constrained tokens (DPoP/mTLS)
- Metadata advertises `access_token_signing_alg_values_supported` when enabled
- F\* spec: `fstar/token/JwtAccessToken.fst` (5 lemmas, 0 admit)
- 6 integration tests in `jwt_access_token_test.rs`

## Roadmap principles (delivery rules)

1. **Tracking comes first**: add RFC stubs/rows to the compliance matrix early (as `planned`) so the backlog is
   explicit, reviewable, and evidence-driven.
2. **Advertise only what we enforce**: metadata MUST NOT claim support for auth methods/features that are not
   implemented end-to-end.
3. **Policy profiles over global toggles**: OAuth 2.0 vs 2.1 compatibility MUST be explicit, per-client/per-connection,
   time-bounded, and auditable.
4. **No secrets in logs or audits**: audit records store identifiers/hashes, not raw tokens/credentials.
5. **Formal definitions first**: before implementing a new RFC surface, enumerate the F*/Tamarin proof obligations
   and map them into compliance matrix rows (see `docs/program-management/initiatives/oauth/oauth-formal-verification-plan.md`).

## Milestones

### M0 — RFC tracking hardening & capability alignment

Objective: make “supported vs not supported” mechanically derivable from `spec/compliance-matrix.yaml` and ensure
metadata aligns with actual behaviour.

Status: complete (2026-02-05).

Scope:
- Add **all missing OAuth WG RFCs** to the compliance matrix as `planned` with an explicit applicability tag
  (`as`, `client`, `rs`, `doc_only`, `not_applicable`).
- Promote “implemented (untracked)” RFCs to tracked rows (even if `planned`/`partial`) with concrete tests.
- Remove or implement any “advertised but not enforced” metadata claims.

Exit criteria:
- `python3 scripts/validation/validate_compliance_matrix.py --check` passes.
- The `/​.well-known/oauth-authorization-server` metadata matches the real supported auth methods and endpoints.

### M1 — OAuth profile system (OAuth 2.0 vs 2.1 selection)

Objective: support OAuth 2.0/2.1 **selectively** without weakening defaults.

Status: largely complete (profile enforcement live; management CRUD delivered in Phase 5).

Current state:
- Runtime policy is sourced from the active PostgreSQL management snapshot. Startup environment
  variables are limited to bootstrap, transport, shared-store, and host-local secret admission.
- Management-plane policy is environment-scoped (`environment_policies` in `db/schema.sql`).
  Client records carry grant/response/scope/auth-method metadata and an optional OAuth profile
  binding; PKCE posture is carried by the active policy/profile, not by per-client columns.
- OAuth profiles are persisted and enforced in `/authorize`, `/token`, DCR, and upstream authorization
  (`crates/server/src/oauth_profile.rs`, `crates/server/src/web/mod.rs`).
- Metadata is generated from the active runtime configuration snapshot and the selected OAuth profile.
- DCR publication and route admission are controlled by the environment-scoped `dcr_enabled`
  database policy field; metadata omits `registration_endpoint` and DCR routes return 404 while
  it is disabled.
- DCR validation gates are environment-scoped database policy fields
  (`dcr_require_pkce_for_public`, `dcr_require_pkce_for_confidential`,
  `dcr_require_sender_constrained`, `dcr_allowed_sender_methods`) enforced by DCR validation.
- Management-plane client/key/user CRUD endpoints are implemented with audit trails and RBAC.
- Audit read endpoints (list, filter, export) are live with cursor-based pagination.
- Policy profile CRUD (`/oauthProfiles`, `/clientPolicyProfile`) is implemented including
  time-bounded exception management and security downgrade detection (H-4).
- Remaining: publication and hosted-evidence hardening for the SDK/admin surfaces is tracked in
  `management-platform-follow-on-plan.md`.

Scope:
- Introduce explicit policy profiles for:
  - **Downstream clients** (AS-side compatibility exceptions).
  - **Upstream connections** (client-side compatibility per upstream IdP).
- Encode profile selection into configuration/persistence with audit trails.
- Define OAuth 2.1 refresh-token sender constraint (v21-006) as a profile policy:
  - DPoP: bind refresh tokens to `cnf.jkt` and require a matching proof on refresh.
  - mTLS: bind refresh tokens to `x5t#S256` and require mutual TLS on refresh.
  - Rotate refresh tokens and audit/metric mismatches.

RFC alignment:
- `draft-ietf-oauth-v2-1` deltas (`planned` rows become implementable).
- RFC 9700 posture is the default profile baseline.

Exit criteria:
- Profiles are observable (audit events + metrics) and time-bounded for exception use.
- OAuth 2.1 draft planned rows move towards verified.

### M2 — Client authentication completeness (RFC 7521 / RFC 7523)

Objective: fully support JWT-based client authentication and remove partial/implicit behaviour.

Status: complete (`private_key_jwt` and `urn:ietf:params:oauth:grant-type:jwt-bearer` are verified;
`client_secret_jwt` is intentionally not supported — see security policy).

Scope:
- Implement and enforce a complete matrix for token endpoint client authentication:
  - `client_secret_basic`, `client_secret_post`
  - `private_key_jwt` (already partially implemented)
  - decide and either **implement or stop advertising** `client_secret_jwt`
- Add jti replay protections and algorithm allow-lists as policy-controlled gates.
- Add strong-audit events for “token issuance with client auth method X”.

Exit criteria:
- RFC 7521/7523 rows exist in compliance matrix and are `verified` (where applicable).
- Metadata’s `token_endpoint_auth_methods_supported` is truthful.

### M3 — Mutual TLS end-to-end (RFC 8705)

Objective: move mTLS from “metadata-only” to “enforced binding” where configured.

Status: complete (verified, with documented limitations).

Scope:
- Enforce `tls_client_auth` / `self_signed_tls_client_auth` at relevant endpoints when enabled.
- Bind access tokens to the client certificate (and reflect via `cnf` where applicable).
- Ensure DCR policy gates for `mtls` declarations match actual enforcement.

Exit criteria:
- RFC 8705 is tracked and verified (including negative tests and operational docs).

### M4 — Proof-of-possession semantics & key identifiers (RFC 7800 / RFC 9278 / RFC 7638)

Objective: standardise PoP semantics across DPoP/mTLS and remove ad-hoc key thumbprint handling.

Status: complete (verified).

Scope:
- Track and validate `cnf` handling for sender-constrained tokens.
- Add support for JWK Thumbprint URI where it improves interoperability (RFC 9278).
- Promote RFC 7638 thumbprint behaviour to tracked+verified.

Exit criteria:
- PoP key identifiers are consistent across AS token issuance, introspection responses, and verification logic.

### M5 — Resource Indicators (RFC 8707)

Objective: support explicit resource/audience selection for multi-API environments.

Status: complete (verified).

Scope:
- Implement `resource` parameter processing (as applicable) and enforce audience-bound tokens.
- Audit all “resource-bound” grants/issuances.

Exit criteria:
- RFC 8707 tracked rows exist and are verified.

### M6 — Token Exchange (RFC 8693) + Rich Authorization Requests (RFC 9396)

Objective: unlock modern delegation/entitlement scenarios in federated environments.

Status: complete (verified).

Scope:
- Token Exchange grant implementation (AS-side) with strict policy gates and audit.
- RAR `authorization_details` parsing, validation, and persistence (PAR/JAR integration).

Exit criteria:
- Both RFCs are tracked with end-to-end tests and artefacts; defaults remain fail-closed.

### M7 — Step-Up Authentication Challenge (RFC 9470)

Objective: enable “step-up” flows without bespoke application glue.

Scope:
- Define step-up signalling, state storage, and enforcement points.
- Integrate with OIDC `acr`/`amr` policy decisions (see OIDC plan).

Exit criteria:
- RFC 9470 is tracked with clear operator guidance and auditable outcomes.

### M8 — Device Authorization Grant (RFC 8628)

Objective: support device/CLI login flows as an opt-in feature.

Status: complete (verified).

Implementation:
- `crates/server/src/device_authz.rs`: 1085-line module implementing `/device_authorization`
  issuance, polling semantics (`authorization_pending`, `slow_down`, `expired_token`), user
  approval, and bounded TTL store with hashed device/user codes at rest (31 tests).
- `fstar/device_authz/DeviceAuthz.fst`: F\* specification with 14 lemmas covering code lifetime,
  single-use, approval binding, and environment isolation.
- `crates/kani-harness/src/bounded_device_authz.rs`: 9 Kani harnesses verifying bounded behaviour.
- `proofs/tamarin/device_auth/device_authorization_security.spthy`: 8 Tamarin lemmas (no token
  without user approval, device code single-use, user code binding, expiry enforcement, etc.).
- `spec/compliance-matrix.yaml`: `rfc_8628` rows (5) with `status: verified`.
- Audit events emitted for issuance, approval, polling, and denial (fail-closed on audit errors).

Exit criteria:
- RFC 8628 tracked rows are verified; operational runbook exists.

### M9 — Introspection JWT response (RFC 9701) + Protected Resource Metadata (RFC 9728)

Objective: improve RS integration and reduce RS↔AS coupling ambiguity.

Status: complete (verified).

Implementation:
- **RFC 9701**: JWT-formatted introspection responses with `iss`/`aud`/`exp`/`iat`/`jti`/`cnf`,
  signed by the AS key manager and aligned with rotation policy. Opt-in via `Accept:
  application/token-introspection+jwt` header.
  - `fstar/introspection/JwtIntrospection.fst`: F\* specification with 5 lemmas.
  - `crates/kani-harness/src/bounded_jwt_introspection.rs`: 6 Kani harnesses.
  - `proofs/tamarin/introspection/jwt_introspection_security.spthy`: 6 Tamarin lemmas (response
    unforgeability, audience/issuer binding, no token swap, jti replay prevention, cross-tenant
    isolation).
  - `spec/compliance-matrix.yaml`: `rfc_9701` rows with `status: verified`.
- **RFC 9728**: `/.well-known/oauth-protected-resource` endpoint for Aegaeon-managed RS components
  (scopes, methods, authorization server linkage, sender-constraint expectations).
  - `crates/server/src/metadata.rs`: Protected Resource Metadata endpoint.
  - `fstar/resource/ProtectedResourceMetadata.fst`: F\* specification with 5 lemmas.
  - `spec/compliance-matrix.yaml`: `rfc_9728` rows with `status: verified`.

Exit criteria:
- Both RFCs are tracked, and RS-facing integration docs exist.

### M10 — SD-JWT (RFC 9901)

Objective: selective disclosure for verifiable credential issuance scenarios.

Status: complete (verified).

Implementation:
- `crates/jose/src/sd_jwt.rs`: Issuer, Holder, and Verifier with salt generation, selective
  disclosure, and combined presentation (24 tests).
- `fstar/jose/Jose.SdJwt.fst`: F\* specification covering disclosure determinism and binding.
- `crates/kani-harness/src/lib.rs`: 6 Kani harnesses verifying bounded behaviour.
- `spec/compliance-matrix.yaml`: `rfc_9901` rows with `status: verified`.

## Appendix — OAuth WG RFC universe (current)

The OAuth WG RFC list used by this roadmap (35 RFCs):

- 6749, 6750, 6755, 6819, 7009,
- 7519, 7521, 7522, 7523,
- 7591, 7592, 7636, 7662,
- 7800, 8176, 8252, 8414,
- 8628, 8693, 8705, 8707, 8725,
- 9068, 9101, 9123, 9126, 9207, 9278, 9396, 9449, 9470,
- 9700, 9701, 9728, 9901

Related RFCs used by Aegaeon features (non-exhaustive):

- JOSE: RFC 7515, 7516, 7517, 7518, 7519
- JWK Thumbprint: RFC 7638
