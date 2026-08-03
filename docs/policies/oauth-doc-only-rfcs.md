# OAuth Doc-Only RFC Posture (6755 / 6819 / 8252 / 9123)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Core/Server

This document records Aegaeon’s **standards-first, fail-closed** posture for RFCs that are
primarily *guidance* and/or *identifier registries* rather than requiring new protocol endpoints.

The authoritative tracker remains `spec/compliance-matrix.yaml`.

## RFC 6755 — OAuth URN Sub-Namespace

RFC 6755 establishes a URN sub-namespace for OAuth-related identifiers.
Aegaeon uses the URN namespace identifiers defined by OAuth-related RFCs and treats them as
**exact-match protocol constants**.

### URN identifiers used by Aegaeon (non-exhaustive)

- `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` (RFC 7523)
- `urn:ietf:params:oauth:grant-type:jwt-bearer` (RFC 7523)
- `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693)
- `urn:ietf:params:oauth:token-type:access_token` (RFC 8693)
- `urn:ietf:params:oauth:request_uri:<value>` (RFC 9126 PAR; request_uri scheme)

Operational policy:
- Unknown URNs are rejected (fail closed).
- Aegaeon does not “best-effort” coerce or normalize grant types or token types beyond trimming.

## RFC 6819 — OAuth 2.0 Threat Model & Security Considerations (Historical)

RFC 6819 is a historical threat model and security considerations document for OAuth 2.0.
Aegaeon treats RFC 9700 (OAuth 2.0 Security BCP) as the primary modern baseline and uses RFC 6819
as supporting context.

### Posture mapping (high level)

- **No implicit / no ROPC by default** (BCP-aligned posture).
- **PKCE (S256)** enforced for authorization code flows based on operator policy.
- **Exact redirect URI matching** and “no fragment” enforcement.
- **Sender-constrained access tokens** (DPoP and/or mTLS) are supported with fail-closed verification.
- **Strong audit baseline**: security-relevant operations are expected to be auditable; deployments
  should treat audit sink failures as operation failures (see `docs/policies/audit-policy.md`).

This posture is evidenced by the BCP and flow-level coverage in `spec/compliance-matrix.yaml`
(notably RFC 9700 / RFC 7636 / RFC 9449 / RFC 9126 entries) and their referenced tests/proofs.

## RFC 8176 — Ambiguity of Uppercase vs Lowercase in RFCs (BCP 14)

RFC 8176 clarifies that the requirement keywords defined by BCP 14 (MUST/SHOULD/MAY/etc.) are
case-insensitive. Aegaeon treats all OAuth/OIDC RFC requirement keywords using RFC 8176 semantics
and does not introduce any additional protocol surface.

## RFC 8252 — OAuth 2.0 for Native Apps (Client Guidance)

Aegaeon supports native-app-friendly best practices without weakening defaults:

- **PKCE (S256)** is the expected posture for public clients.
- Redirect URIs are validated as follows:
  - MUST be absolute URIs and MUST NOT include fragments.
  - MUST use `https` **except** loopback redirects (`http://localhost` or `http://127.0.0.1`).

### Out of scope (explicit)

- Custom-scheme redirects (e.g. `com.example.app:/callback`) are intentionally not supported by the
  default redirect validation policy, because they are commonly deployed incorrectly and hard to
  audit safely without an explicit allow-list model.

## RFC 9123 — OAuth 2.0 for Browser-Based Applications (Client Guidance)

Aegaeon’s default posture matches modern browser guidance:

- Implicit grant is forbidden; authorization code + PKCE is the supported browser-friendly flow.
- Public clients should avoid storing long-lived credentials/tokens in browser storage; prefer a
  BFF (backend-for-frontend) pattern or short-lived tokens with sender-constraints when possible.

Operational note:
- Aegaeon does not attempt to “compensate” for insecure client storage patterns; instead it
  provides policy gates (PKCE, sender constraints, refresh rotation) and relies on deployers to
  choose a safe client architecture.
