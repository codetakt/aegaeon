# SAML Facade Policy (RFC 7522)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Core/Server

This policy records that the Aegaeon core server does not implement RFC 7522
(SAML 2.0 profile for OAuth client authentication and authorization grants).
SAML assertions are terminated by an external facade.

## Scope

- Aegaeon core MUST NOT accept
  `grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer`.
- Aegaeon core MUST NOT advertise the SAML grant in metadata or DCR.
- The SAML facade is responsible for XML signature validation, assertion
  conditions, replay detection, and audience checks.

## Integration Pattern

- The facade exchanges verified SAML assertions for OAuth tokens using:
  - RFC 7523 (JWT bearer), or
  - RFC 8693 (Token Exchange).
- The facade is the only component that processes SAML assertions.

## Compliance Tracking

- `spec/compliance-matrix.yaml` records RFC 7522 as `not_applicable` for the
  Aegaeon core server.
- Any future decision to implement RFC 7522 in-core requires a security
  review, verification plan, and updated compliance status.
