# JWT Bearer Grant Policy (RFC 7523)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Core/Server

This policy documents the operational posture for the JWT Bearer authorization
grant (`urn:ietf:params:oauth:grant-type:jwt-bearer`) and the optional
management-database policy that permits `sub == client_id` assertions.

## Rationale

- Preserve JWT kind separation (RFC 8725) between `private_key_jwt` client
  authentication and JWT bearer authorization grants.
- Fail closed by default to avoid confusing client-auth assertions with
  authorization grants.
- Provide an operator-controlled, database-backed escape hatch for deployments
  that need `sub == client_id` semantics.

## Default Posture

- JWT bearer grant is **disabled** unless the active PostgreSQL Environment
  policy includes `urn:ietf:params:oauth:grant-type:jwt-bearer` in
  `policy.allowedGrantTypes`.
- `sub == client_id` is **rejected** by default to keep grant types mutually
  exclusive with `private_key_jwt`.
- `openid` scope is rejected for JWT bearer grants.

## Configuration

- `policy.allowedGrantTypes`
  - Enables the JWT bearer grant only when it contains
    `urn:ietf:params:oauth:grant-type:jwt-bearer`.
- `policy.jwtBearerAllowClientSubject`
  - Allows `sub == client_id` **only** when the assertion targets the issuer
    audience (see Audience Profiles below). Default is `false`.
- `policy.clientJwtAllowedAlgs`
  - Allow-list for JWT bearer assertion algorithms. The promoted server claim
    currently includes the narrow `RS256 Interop Slice`; broad RSA and
    non-promoted JWT algorithm surfaces remain outside the strong-constraint
    claim.
- `policy.clientJwtRequireKid`
  - Requires a `kid` header for JWT bearer assertions.
- `policy.jwtBearerJtiWindowSeconds`
  - Replay window for JWT bearer `jti` values.
- `policy.jwtLeewaySeconds`
  - Clock-skew leeway for `exp`/`nbf`/`iat` checks.

## Audience Profiles

### Standard JWT Bearer (default)

- `iss` must be `client_id`.
- `sub` must be non-empty and **must not** equal `client_id`.
- `aud` **must include** `{issuer}/token`.

### Client-Subject JWT Bearer (opt-in)

Enabled only when `policy.jwtBearerAllowClientSubject=true` in the active
PostgreSQL Environment policy:

- `iss` must be `client_id`.
- `sub` **may** equal `client_id`.
- `aud` **must include** `{issuer}`.
- `aud` **must not include** `{issuer}/token`.

This keeps the grant distinct from `private_key_jwt` and prevents JWT
substitution across contexts.

## Claim Requirements

JWT bearer assertions are validated with the following requirements:

- Required: `iss`, `sub`, `aud`, `exp`.
- Optional: `nbf`, `iat`, `jti` (if `jti` is present, replay is rejected within
  the configured window).

## Operational Guidance

- Use **client_credentials** for client-only access. Prefer JWT bearer only
  when the client is acting on behalf of another subject.
- If enabling `policy.jwtBearerAllowClientSubject`, restrict scope and
  rotate client keys aggressively. Treat it as a compatibility path, not
  a default posture.
- Keep algorithm allow-lists narrow and require `kid` in production.

## DCR and Metadata

- DCR validation only permits registering the JWT bearer grant when the active
  PostgreSQL Environment policy allows it.
- Metadata advertises the JWT bearer grant only when the active Environment
  policy allows it.

## Verification Alignment

- F* model: `fstar/auth/Pkjwt.fst` encodes the audience profiles and subject
  constraints used by the runtime.
- Tamarin model: `proofs/tamarin/jwt_bearer/jwt_bearer_security.spthy` validates
  JWT bearer integrity and replay properties.
- Runtime tests: `crates/server/tests/jwt_bearer_grant_http_test.rs` covers
  allow/deny behavior for both profiles.
- Claim posture: the `RS256` JWT bearer assertion path is part of the promoted
  `RS256 Interop Slice`; broad RSA and non-promoted interoperability surfaces
  remain outside the current verified allowlist.
