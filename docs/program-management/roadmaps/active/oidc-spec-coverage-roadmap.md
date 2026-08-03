# OIDC Spec Coverage Roadmap (OP + OIDC RP)

Last updated: 2026-03-30

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This roadmap tracks Aegaeon’s coverage of **OpenID Connect (OIDC)** and adjacent OIDC/OIDF
specifications across two roles:

- **OP**: OpenID Provider (Aegaeon’s default role when the active Environment policy enables OIDC).
- **OIDC RP**: Relying Party / OIDC Client when brokering to upstream IdPs (SoT) for federation use cases.

The **authoritative** status tracker remains `spec/compliance-matrix.yaml`. This document is a
human-readable gap analysis and planning aid, not a replacement.

## Status levels

- **Verified (tracked)**: backed by tests/proofs and recorded in `spec/compliance-matrix.yaml`.
- **Implemented (untracked)**: code exists but is not yet tracked/evidenced in the matrix.
- **Planned**: intended, but not implemented.
- **Not supported (intentional)**: explicitly out of scope or deliberately disabled for security posture.

## Current snapshot (what is verified today)

### OP / IdP (verified)

The following OIDC capabilities are tracked as `verified` in `spec/compliance-matrix.yaml`:

- **OIDC Core** (Authorization Code + PKCE; ID Token issuance/validation; UserInfo; nonce/max_age; at_hash/c_hash)
  - Matrix sections: `openid_core` (OIDC-1-001…OIDC-1-008)
  - Enablement: active Environment policy (`policy.oidcEnabled`; see
    `docs/configurations/environment/README.md`)
- **OIDC Discovery** (`/.well-known/openid-configuration`)
  - Matrix section: `openid_discovery` (OIDC-2-001)
- **OIDC DCR policy contract** (OIDC-specific metadata constraints on top of OAuth DCR)
  - Matrix section: `openid_dcr` (OIDC-2-002)
- **OIDC JWKS publication & rotation overlap**
  - Matrix section: `openid_jwks` (OIDC-2-003)
- **Logout**
  - RP-Initiated Logout: `openid_logout` (OIDC-3-001/002)
  - Back-Channel Logout (Logout Token + retry/idempotency semantics): `openid_logout` (OIDC-3-003…OIDC-3-005)
- **OAuth 2.0 Form Post Response Mode** (used by OIDC RPs)
  - Matrix section: `oauth_form_post` (OIDC-4-001/002)
- **JAR / Request Object** (incl. optional encrypted Request Objects when configured)
  - Matrix sections: `openid_jar` (OIDC-5-001) and `rfc_9101`

Current boundary note:

- The promoted server claim now includes both the `RS256 Required Slice`
  (OIDC Core ID Tokens) and the narrow `RS256 Interop Slice` (signed Request
  Objects, direct `request=`, PAR `request_uri`, and `private_key_jwt` when
  they use `RS256`).
- The remaining OIDC matrix hardening work is now focused on continuous
  monitoring evidence, not on closing the basic `RS256` runtime boundary or
  JWKS overlap invariants.
- Concretely, that means keeping the dudect evidence current for the existing
  compare / HMAC / Ed25519 / RSA / JWE harnesses and extending it only if new
  secret-dependent OIDC glue is introduced.

### Matrix triage note (2026-03-30)

The remaining non-`verified` OIDC-adjacent rows in `spec/compliance-matrix.yaml`
are intentionally left that way for now:

- `OIDC-1-008` remains `implemented` because it is a continuous-monitoring row
  backed by dudect evidence, not a natural F\*/Tamarin-style proof row.
- `7523-001`, `7523-115`, and `7523-401` remain `implemented` because they are
  broad runtime-support rows that cover wider JWT bearer / `private_key_jwt`
  behaviour than the narrow promoted `RS256` slices.

Current policy is to keep those rows as-is unless a future claim needs narrower
sub-slices. If that happens, the correct move is to split the broad row and add
new claimable rows, not to overstate the scope of the current verified slice.

### OIDC RP (upstream IdP brokering)

Aegaeon now provides a runtime **OIDC RP surface** for brokering to upstream IdPs:

- **Routes**: `/oauth/upstream/:connection/authorize`, `/oauth/upstream/:connection/callback`,
  `/oauth/upstream/refresh` are implemented and routed in `crates/server/src/web/mod.rs`.
- **Upstream discovery/JWKS**: fetched and cached per upstream issuer; ID Token signature verification
  uses the upstream JWKS with algorithm allow-list enforcement.
- **Account linking**: `account_links` table with environment-scoped lookups, auto-provisioning of
  end_users, privacy-preserving upstream sub hashing (SHA-256 + base64url).
- **Trust chain verification**: federation trust chain is re-verified on callback (T-RP-2 fix);
  HTTPS-only upstream HTTP client (T-RP-1).
- **Audit trails**: upstream callback and refresh operations emit audit events.
- **Connection management**: CRUD endpoints in `crates/server/src/web/management.rs` (connections).
- **Federation PostgreSQL repos**: trust anchors, entity cache, trust chain cache with environment
  isolation (Phase 5).
- **Security**: C-4 (cross-tenant isolation) and C-5 (upstream refresh scoping) fixed.
- **Upstream refresh rotation**: OIDC-1-009 verified (Phase 7) — F\* `UpstreamRefresh.fst` with 17
  lemmas, e2e tests with mock IdP (`crates/server/tests/upstream_e2e_test.rs`).
- **SSRF defense**: Phase 8 — `crates/server/src/ssrf.rs` provides private IP blocking (IPv4/IPv6/
  IPv4-mapped), DNS pre-flight validation, and redirect policy (HTTPS, domain allowlist, max 3).
- **Trust Mark verification**: Phase 8 — JWS signature check, claims validation (iss/sub/iat/exp/id),
  status URI check, `max_path_length` enforcement, `intersect` operator. F\* `TrustMark.fst` (5
  lemmas, 0 admit).
- **LRU cache**: Phase 8 — entity and trust chain caches have bounded eviction (configurable via
  `policy.federationCacheMaxEntries`, default 1000).
- **Tests**: `crates/server/tests/upstream_refresh_test.rs`, `upstream_e2e_test.rs`, and compliance
  matrix RP rows.

Remaining for production readiness: UI/SDK surfaces, end-to-end integration tests with real upstream
IdPs, and operational runbooks for connection onboarding.

## Explicit non-support / gaps (OP)

The following are either intentionally disabled or not implemented today:

- **Implicit / Hybrid flows**: not supported (`response_types_supported=["code"]`).
- **Pairwise subject identifiers**: not supported (`subject_types_supported=["public"]` only).
- **`claims` parameter**: not supported (`claims_parameter_supported=false`).
- **`request` parameter**: supported; direct Request Objects and `request_uri` now share the same authorization-path validation boundary.
- **ID Token encryption**: not supported (no `id_token_encryption_*` support advertised).
- **Signed/Encrypted UserInfo responses**: not supported (no `userinfo_*` signing/encryption support advertised).
- **OIDC Session Management 1.0** (`check_session_iframe`): intentionally not implemented. RFC 9700 (OAuth 2.0 Security BCP) does not recommend iframe-based session management due to cross-origin restrictions and third-party cookie deprecation. Back-Channel Logout is the recommended approach.
- **OIDC Front-Channel Logout 1.0**: intentionally not implemented. Unreliable in modern browsers due to third-party cookie blocking (Safari ITP, Chrome Privacy Sandbox). Back-Channel Logout (OIDC-3-003…005) provides reliable server-to-server logout notification.
- **WebFinger** (`/.well-known/webfinger`): not implemented.
- **`RS256` verification-boundary status**: the mandatory OIDC Core
  `RS256 Required Slice` is now closed as a promoted boundary exception for the
  server claim. The `RS256 Interop Slice` (`request_uri`, signed Request
  Objects, `private_key_jwt`) is also now closed as a promoted server-claim
  exception. Broad RSA / non-`RS256` JOSE interoperability remains compat.

## Roadmap (next additions)

1. **Keep the `RS256 Required Slice` evidence current**
   - Preserve the promoted OP ID Token `RS256` issuance / validation boundary.
   - Keep Discovery / DCR / runtime consistency (`id_token_*`) aligned with the promoted slice.
   - Keep the scope intentionally narrow: this remains an OIDC-required carve-out, not a claim of general-purpose RSA verification.
2. **Keep the `RS256 Interop Slice` evidence current**
   - Keep signed Request Objects, direct `request=`, PAR `request_uri`, and
     `private_key_jwt` on the promoted `RS256` interoperability verifier path.
   - Keep matrix / assurance wording / runtime behaviour aligned so the narrow
     exception remains explicit and defensible.
   - Keep non-`RS256` RSA and broader JOSE algorithm families in compat unless
     separately justified.
3. **Matrix hardening (triage first)**
   - Keep the remaining non-`verified` rows explicitly classified as either
     continuous-monitoring evidence (`OIDC-1-008`) or broad runtime-support
     rows (`7523-001`, `7523-115`, `7523-401`).
   - If future work needs stronger wording, split those rows into narrower
     claimable sub-slices instead of widening the current claim boundary.
4. **OIDC RP mode (upstream IdP brokering)** — Implemented and verified (Phase 5–8)
   - Upstream connections with discovery, JWKS, account linking, and audit are live (Phase 5).
   - Upstream refresh rotation verified: F\* 17 lemmas + e2e tests (Phase 7, OIDC-1-009).
   - SSRF defense, Trust Mark verification, LRU cache, `max_path_length`, `intersect` (Phase 8).
   - Remaining: end-to-end tests with real upstream IdPs, UI/SDK, operational runbooks.
5. **Session management & front-channel logout** (intentionally deferred)
   - Session Management 1.0 is not recommended by RFC 9700 BCP (iframe-based, vulnerable to 3rd-party cookie deprecation). Front-Channel Logout is unreliable in modern browsers. Back-Channel Logout is the correct security posture and is already verified. Reassess only if browser ecosystem changes make these viable again.
6. **Optional protocol surface expansion**
   - Consider adding `claims` parameter, signed UserInfo, JARM, and FAPI profiles once the operational platform is in place
     (tracked in `docs/program-management/roadmaps/future/future-projects.md`).

## Appendix: OIDC/OIDF specs considered

This list is the baseline “coverage set” for this roadmap (not all are implemented today):

- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0
- OpenID Connect Dynamic Client Registration 1.0
- OpenID Connect Session Management 1.0
- OpenID Connect Front-Channel Logout 1.0
- OpenID Connect Back-Channel Logout 1.0
- OpenID Connect RP-Initiated Logout 1.0
- OAuth 2.0 Form Post Response Mode
- OpenID Connect Federation 1.0 (RP-side federation brokering and repository-backed trust-chain
  state implemented in Phase 5; OP-side public entity configuration, subordinate statements,
  fetch/list/resolve endpoints are deferred and compliance matrix `openid_federation_op` rows are
  planned until OP signing enters the verified runtime boundary)
- JWT Secured Authorization Request (JAR) — RFC 9101 (implemented/verified)
