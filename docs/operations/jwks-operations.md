# JWKS Operations

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Overview

- The Authorization Server (AS) publishes its own JWKS at:
  - `/jwks`
  - `/.well-known/jwks.json` (compatibility)
- OAuth discovery metadata exposes this via `jwks_uri`.
- The server also fetches *client* JWKS (via a client `jwks_uri`) for client authentication flows such as `private_key_jwt`.
  See: `docs/operations/private-key-jwt.md`.

## JWKS Publication (AS keys)

- `jwks_uri` in `/.well-known/oauth-authorization-server` points to AS public keys (not client keys).
- When OIDC is enabled, the `/jwks` response is derived from ACTIVE and RETIRING
  `OIDC_ID_TOKEN_SIGNING` runtime keys in `aegaeon.runtime_keys`.

## Client JWKS Fetch (`jwks_uri` hardening)

Key knobs (see `docs/configurations/environment/README.md` for the canonical list):
- HTTP/retries, cache TTL, refresh skew, circuit, body cap, stale policy, and `kid` reuse policy:
  management database fields under `policy.jwks*`
- TLS trust: `AEGAEON_JWKS_CA_BUNDLE`, `AEGAEON_JWKS_INSECURE_SKIP_VERIFY` (development only)
- Body pin: `AEGAEON_JWKS_PIN_SHA256`
- Shared runtime state: `AEGAEON_JWKS_REDIS_URL`
- Optional shared body cache: `AEGAEON_JWKS_SHARED_CACHE_PATH`

Monitoring:
- The JWKS fetcher exports counters/latency series and circuit/stale labels.
  See: `docs/operations/monitoring/README.md`.

## Security Notes

- Prefer HTTPS for `jwks_uri` and configure a CA bundle/pinning as needed.
- Cap response size; fail closed on malformed JSON or mismatched pin.
- Keep `kid` unique per key material; do not reuse `kid` with different keys unless explicitly allowed by policy.
- In multi-node deployments, use `AEGAEON_JWKS_REDIS_URL` whenever remote client JWKS can affect
  `private_key_jwt` or JWT bearer verification. Redis coordinates circuit state, half-open probes,
  stale generation limits, and `kid` fingerprint history. The on-disk shared cache is only a cache
  of fetched JWKS response bodies.

## Key Rotation Guide

### Authorization Server (AS keys)

- Rotate OIDC signing keys through the management API `runtimeKeys` endpoints.
- The KMS/HSM-backed OIDC signing path is tracked in
  `docs/design/oidc-kms-signing-design.md`; hosted bootstrap can create a provider `awsKms`
  OIDC signing runtime key, while the general management API currently accepts provider `databaseEncrypted`.
- Ensure `kid` uniqueness per key material; never reuse a `kid` for different keys.
- OIDC ID Token signing key rotation (recommended overlap pattern):
  1. Create a NEXT `OIDC_ID_TOKEN_SIGNING` runtime key with a fresh `kid`.
  2. Activate that NEXT key through the management API; the previous ACTIVE key becomes RETIRING.
  3. Revoke the RETIRING key after the maximum ID Token TTL has elapsed.

### Server-side fetcher (this project)

- Uses HTTPS + CA bundle + optional pinning; retries with backoff; caps body size.
- Caches JWKS (ETag/Last-Modified/Cache-Control). Background refresh near expiry.
- Detects duplicate `kid` and `kid` reuse with different material according to management policy.
- Supports shared on-disk body cache (`AEGAEON_JWKS_SHARED_CACHE_PATH`) with GC.
- Supports Redis-backed shared runtime state (`AEGAEON_JWKS_REDIS_URL`) for multi-node circuit,
  stale-generation, probe, and `kid` reuse coordination.
