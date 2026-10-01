# OIDC RP Brokering Specification

Last updated: 2026-10-01

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Purpose

This document specifies the current upstream IdP brokering boundary where Aegaeon acts as an OIDC RP
to external Identity Providers, enabling federated authentication flows.

This document is the canonical current specification for the delivered broker / federation
control-plane posture. The completed Phase B delivery record remains in
`docs/program-management/historical/roadmaps/federated-broker-idp-delivery.md`.

This specification does not widen the released verification claim by itself.

## Implemented Runtime And Control-Plane Boundary

The current broker baseline includes:

- upstream authorization, callback, refresh, and logout relay runtime routes
- upstream discovery and JWKS caching with HTTPS and outbound-domain admission
- environment-scoped account-link storage, search, explicit link, unlink, relink, conflict
  preview/resolution, and bulk relink operations
- broker JIT provisioning controls for enablement, email-domain allowlists, verified-email policy,
  collision policy, and initial local status
- attribute mapping from upstream claims into local profile state
- downstream custom-claim release policy for ID Token and UserInfo surfaces
- trust-anchor inventory, entity-cache diagnostics, trust-chain diagnostics, refresh, and eviction
  operations
- federation logout posture, front-channel upstream logout relay, durable logout-recovery
  incidents, and operator clear flows
- audit events for federation configuration, mapping, claim release, account-link, trust
  diagnostics, logout posture, runtime relay, and recovery operations
- generated management-client and sibling admin-console surfaces for the same day-2 operations

Configuration transactions are the current federation-management surface. A separate top-level
federation resource is not required for the delivered posture.

## Upstream Discovery Endpoint Admission

The server validates upstream OIDC discovery metadata before using any discovered endpoint. The
following discovery members are admitted under the same endpoint policy:

- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`
- optional `end_session_endpoint`

Each admitted endpoint MUST be an absolute URL with a host, MUST use `https`, MUST NOT contain
userinfo credentials, and MUST NOT contain a query or fragment component. Rust test builds may use
loopback `http` endpoints for local mock providers only; this exception is not part of the
production runtime boundary.

When `policy.upstreamOutboundAllowedDomains` is non-empty, every admitted upstream discovery
endpoint, including the optional `end_session_endpoint`, MUST match the configured allowlist. Literal
non-routable hosts are rejected during metadata/redirect admission. Server-performed discovery,
token, JWKS, and upstream refresh HTTP calls additionally use the upstream SSRF policy's DNS/private
target checks and redirect policy.

OIDC treats `end_session_endpoint` as optional. Aegaeon keeps that protocol optionality, but if the
provider publishes `end_session_endpoint`, the value is admitted fail-closed under the same upstream
outbound policy as the mandatory discovery endpoints. This avoids a weaker logout-only URL path and
prevents the server from appending relay state to a provider-supplied URL that already carries a
query or fragment.

## Upstream Authorization Browser Binding

Each authorization stores the SHA-256 digest of an independent 256-bit random browser secret.
The secret is sent only in a per-transaction `__Host-aegaeon-upstream-<state-sha256>` cookie with
`Secure; HttpOnly; SameSite=Lax; Path=/`, no Domain, and a lifetime bounded by the configured
authorization lifetime. Positive fractional seconds round up for cookie expiry; the store enforces
the transaction deadline independently. The secret is never included in the upstream authorization
URL or persisted in Redis. The cookie-issuing redirect sends `Cache-Control: no-store` and
`Pragma: no-cache`.
Different pending authorizations use distinct cookies so separate browser tabs can finish independently.

Success and upstream-error callbacks require exactly one well-formed matching cookie across all
Cookie headers. The store atomically checks the digest, the original callback URI reconstructed
from the configured base URL and connection route, and expiry before consuming the transaction.
Missing, malformed, duplicated or mismatched cookies and wrong routes do not consume it. State
alone is insufficient. Only one matching callback can proceed, and backend failures fail closed.
Issuer validation also applies before an upstream error can redirect to the saved return location.
Every response after consumption expires that transaction's cookie, preserving other pending
transaction cookies and any new login session cookie. Existing successful-login connection
currentness, PKCE, nonce, token validation and session checks still apply.

This implements Aegaeon's browser binding for the OAuth client CSRF protections in
[RFC 6749 section 10.12](https://www.rfc-editor.org/rfc/rfc6749#section-10.12) and
[RFC 9700 section 4.7](https://www.rfc-editor.org/rfc/rfc9700#section-4.7).

### Upgrade And API Compatibility

Upstream authorization keys now use storage version `upstream-auth:v2`. Deploy authorization
writers and callback consumers together, draining or stopping old instances before resuming
upstream login traffic. Mixed old/new callback instances are unsupported: the new namespace
prevents old state-only consumers from accepting new transactions, but old instances retain their
old behavior for old records. In-flight legacy authorizations must be restarted. Old records
without a valid browser digest are never accepted by the new callback gate and can expire naturally.
No database migration or new configuration setting is required.

Rust callers constructing `UpstreamAuthRequest` must provide `browser_binding_digest`.
The state-only `try_consume` / `try_consume_async` APIs are replaced by
`try_consume_bound` / `try_consume_bound_async`, requiring the browser digest and expected callback
URI. The serialized digest remains optional for legacy decoding; absence never grants access.

## Front-Channel Upstream Logout Relay

When brokered upstream logout is enabled for a connection, Aegaeon appends `logout_hint`,
`post_logout_redirect_uri`, and relay `state` only after the discovered `end_session_endpoint` has
passed endpoint admission and the stored endpoint still satisfies the current active upstream
outbound policy at logout time. A preexisting query or fragment on that endpoint suppresses the
front-channel redirect target fail-closed.

Unknown or incomplete upstream logout results remain handled by the logout-recovery model in
`federation-logout-recovery-spec.md`; endpoint admission does not claim that the upstream OP actually
destroyed its own session.

## Account Linking Requirements

Account-link operations must remain environment-scoped and auditable. Relink, conflict-resolution,
and bulk-relink flows fail closed when a moved link stores an upstream refresh token unless the
operator explicitly chooses `clear` or `retain`. Low-confidence reassignment and reassignment to a
non-`ACTIVE` target user also require explicit operator acknowledgement.

## Mapping And Claim Release Requirements

Attribute mapping supports direct copy, lower-case normalization, and group mapping for supported
targets such as `email`, `email_verified`, `name` / `display_name`, and non-reserved custom claims.
Mapped values synchronize into the local profile surface used by downstream ID Token and UserInfo
issuance.

Broker-managed custom claims must be explicitly allowed per downstream surface. Blocked
broker-managed custom claims may remain in local profile storage but are not released downstream.
UserInfo custom-claim release still requires `profile` scope.

## Logout Recovery Requirements

Front-channel upstream logout relay uses durable incident records as the source of truth. Successful
callbacks mark incidents `completed`; timed-out callbacks mark incidents `expired`; replayed or
already-resolved callbacks are rejected and audited. Active incidents affect subsequent upstream
authorization according to the configured recovery policy (`force_prompt_login` or
`disable_connection`).

## References

- Existing test harness: `crates/server/tests/oidc_rp_flow_test.rs`
- Management plane connections container: `management-plane/README.md`
- Logout recovery: `federation-logout-recovery-spec.md`
- Delivery record: `../program-management/historical/roadmaps/federated-broker-idp-delivery.md`
- Tamarin models: `proofs/tamarin/federation/rp_brokering.spthy`
