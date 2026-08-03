# JWT Bearer Grant Operations (RFC 7523)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Overview

- This document covers operational guidance for the JWT Bearer authorization grant
  (`urn:ietf:params:oauth:grant-type:jwt-bearer`).
- The policy posture is defined in `docs/policies/jwt-bearer-policy.md`.
- Canonical env var reference: `docs/configurations/environment/README.md`.

## When to Use

- Prefer `client_credentials` when the client is acting on its own behalf.
- Use JWT bearer when the client is acting on behalf of another subject and
  the subject cannot authenticate directly.

## Audience Profiles

### Standard JWT Bearer (default)

- `iss` must equal `client_id`.
- `sub` must be non-empty and **must not** equal `client_id`.
- `aud` **must include** `{issuer}/token`.

### Client-Subject JWT Bearer (opt-in)

Enabled only when `policy.jwtBearerAllowClientSubject=true`:

- `iss` must equal `client_id`.
- `sub` **may** equal `client_id`.
- `aud` **must include** `{issuer}`.
- `aud` **must not include** `{issuer}/token`.

This keeps JWT bearer assertions mutually exclusive from `private_key_jwt` and
prevents substitution across contexts (RFC 8725).

## Configuration

- Include `urn:ietf:params:oauth:grant-type:jwt-bearer` in `policy.allowedGrantTypes` to enable
  the grant.
- `policy.jwtBearerAllowClientSubject=true` allows `sub == client_id` under the
  issuer-audience-only profile above.
- `policy.clientJwtAllowedAlgs` / `policy.clientJwtRequireKid` apply to JWT bearer
  assertions.
- `policy.jwtBearerJtiWindowSeconds` controls replay detection for `jti`.

## Operational Guidance

- Keep `policy.jwtBearerAllowClientSubject=false` unless you are supporting a
  legacy integration that cannot use `client_credentials`.
- Require `kid` in production and keep algorithm allow-lists narrow.
- Treat `sub == client_id` as a compatibility path and restrict scope and
  token TTL where possible.

## Testing

- Runtime coverage: `crates/server/tests/jwt_bearer_grant_http_test.rs`.
- Verification: `fstar/auth/Pkjwt.fst` (F*) and
  `proofs/tamarin/jwt_bearer/jwt_bearer_security.spthy` (Tamarin).
