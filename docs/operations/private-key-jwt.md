# private_key_jwt Operations (jwks_uri / RSA n,e)

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Overview

- Clients authenticate to the token/device authorization/introspection/revocation/PAR endpoints with `private_key_jwt`.
- For RSA keys, the Authorization Server resolves the client's public key from `jwks_uri`
  (JWK with `kty=RSA`, `n`, `e`) and verifies RS256 signatures.
- JWKS fetcher hardening knobs (timeouts/retries/stale/circuit/shared-cache/pinning) are documented in:
  - `docs/operations/jwks-operations.md`
  - `docs/operations/monitoring/README.md`
- Canonical env var reference: `docs/configurations/environment/README.md`.
- **Verification-boundary note**: this server-side `RS256` `private_key_jwt` verification path is
  part of the promoted `RS256 Interop Slice`. Broad RSA and non-promoted interoperability surfaces
  remain outside the general verified allowlist.

## Client identification

Send both `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
and the signed JWT in `client_assertion`. At `/token`, `/device_authorization`,
`/introspect`, and `/revoke`, the outer `client_id` may be omitted (RFC 7521
section 4.2). The assertion's nonempty `sub` identifies the registered client;
Aegaeon requires `iss` to identify that same client. Any nonempty outer
`client_id` must match exactly. An unverified subject is only a lookup hint:
registered method, algorithm, key, signature, audience, time, and replay checks
must all succeed before the request is authenticated.

Plain `/par` requests still require the outer authorization parameter `client_id`,
including when authenticating with HTTP Basic or an assertion (RFC 9126
section 2.1). Requests that previously relied on Basic authentication to supply
this plain-PAR parameter must add it. With a signed Request Object (section 3),
Basic or assertion authentication may identify the client without outer
`client_id`; the verified Request Object must contain the same `client_id`.

Do not combine authentication methods. Zero-length form values are omitted;
if both assertion fields are empty, no assertion method is supplied. Nonempty
incomplete, malformed, whitespace, or unsupported assertion credentials are
rejected even when endpoint policy permits
public clients. Unauthenticated token, device, revocation and PAR requests still
need their own client identification. Use a new assertion `jti` for each request.
The existing endpoint-specific assertion audience checks remain in effect.

## Operational Pattern (Recommended)

- Use `jwks_uri` in client registration; avoid embedding raw keys; publish stable `kid` and rotate by adding new keys then deprecating old ones.
- Enable caching with ETag/Last-Modified on the JWKS endpoint; ensure short TTL; support conditional GETs.
- Configure policy in the management database runtime snapshot:
  - Allowed algorithms: `policy.clientJwtAllowedAlgs` / DCR client metadata policy.
  - Require `kid`: `policy.clientJwtRequireKid=true` (recommended).
  - Enable `private_key_jwt`: `policy.privateKeyJwtEnabled=true`.
- Rotate keys with overlapping validity and unique `kid` per key; do not reuse `kid` with different material.

## E2E Test (RSA via jwks_uri)

- The repository includes an integration test that verifies RS256 signatures using `n`/`e` from a JWKS served over HTTP.
- Test file: `crates/server/tests/pkjwt_jwks_uri_rsa_e2e.rs`
- This test is ignored by default and reads fixtures from environment variables to avoid embedding sensitive material.

### Run the test

```bash
# Provide fixtures (prefer local files for PEM)
export AEGAEON_TEST_ALLOW_NET=1
export AEGAEON_TEST_RSA_FIXTURES=1
export AEGAEON_RSA_PRIV_PEM=@/path/to/rsa-private.pem   # prefix @ to read from file
export AEGAEON_RSA_PUB_PEM=@/path/to/rsa-public.pem     # optional, else tests/fixtures or fallback
export AEGAEON_RSA_JWK_N=...                            # base64url(n)
export AEGAEON_RSA_JWK_E=AQAB                           # base64url(e), default 65537
export AEGAEON_RSA_JWK_KID=test-kid-rsa

cargo test -p aegaeon-server --test pkjwt_jwks_uri_rsa_e2e -- --ignored --nocapture
```

### Generate fixtures (OpenSSL + Python cryptography)

```bash
# Generate a 2048-bit RSA key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_priv.pem

# Derive JWK n/e in base64url
python3 - << 'PY'
from cryptography.hazmat.primitives import serialization
from base64 import urlsafe_b64encode
def b64u_int(i):
    l = (i.bit_length()+7)//8
    return urlsafe_b64encode(i.to_bytes(l,'big')).rstrip(b'=').decode('ascii')
with open('rsa_priv.pem','rb') as f:
    key = serialization.load_pem_private_key(f.read(), password=None)
pub = key.private_numbers().public_numbers
print('AEGAEON_RSA_JWK_N='+b64u_int(pub.n))
print('AEGAEON_RSA_JWK_E='+b64u_int(pub.e))
PY
```

## Notes

- The test spins up a local JWKS HTTP server and registers a client with `jwks_uri` pointing to it.
- The client assertion is signed with the provided RSA private key (RS256). The server fetches the JWKS, selects the key by `kid`, constructs a decoding key from `n`/`e`, and verifies the signature and claims (iss/sub/aud/exp/jti replay).
- For CI, fixtures can be injected via GitHub Secrets or a private artifacts store; do not commit private keys.

## Security Considerations

- Always require `kid` for `private_key_jwt` (operational best practice).
- Prefer `jwks_uri` over inline `jwks` for rotation and caching robustness.
- Configure JWKS pinning/stale policy through the management runtime policy and shared JWKS Redis
  state. Environment variables are reserved for system endpoints such as Redis URLs and CA bundles.
