# OAuth Supporting Standards and Client Guidance

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Core/Server

This document records Aegaeon’s **standards-first, fail-closed** posture for RFCs that are
primarily *guidance* and/or *identifier registries* rather than requiring new protocol endpoints.

The [server standards baseline](../verification/claims/assurance-case/standards-baseline.md)
defines editions and role applicability; `spec/compliance-matrix.yaml` indexes
evidence. Guidance may contain applicable server requirements even when it adds
no endpoint. This document does not attest completed conformance.

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

## RFC 8174 — Requirement Keyword Interpretation (BCP 14)

RFC 8174 updates RFC 2119: only UPPERCASE uses have the defined special meanings.
The former statement that RFC 8176 made keywords case-insensitive was incorrect.

## RFC 8176 — Authentication Method Reference Values

RFC 8176 defines `amr` values. Emitted and consumed values must represent the
actual authentication methods under the server assurance contract's G-09.
The previous `8176-001` not-applicable classification was incorrect; evidence
reconciliation is now planned. A configurable ACR label does not prove MFA.

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

## Browser-Based Applications — draft-ietf-oauth-browser-based-apps-27

The baseline pins draft-27 (2026-07-06). The former RFC 9123 attribution was
incorrect; `browser-apps-001` replaces `9123-001`. Server-facing requirements
must be inventoried separately from assumptions about external client code.

Aegaeon’s default posture matches modern browser guidance:

- Implicit grant is forbidden; authorization code + PKCE is the supported browser-friendly flow.
- Public clients should avoid storing long-lived credentials/tokens in browser storage; prefer a
  BFF (backend-for-frontend) pattern or short-lived tokens with sender-constraints when possible.

Operational note:
- Aegaeon does not attempt to “compensate” for insecure client storage patterns; instead it
  provides policy gates (PKCE, sender constraints, refresh rotation) and relies on deployers to
  choose a safe client architecture.
