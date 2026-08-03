# Networking & TLS enforcement (reverse proxy)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This document describes how Aegaeon enforces RFC 6750 §5 and RFC 9700 transport expectations when
TLS terminates at a fronting reverse proxy (nginx / Envoy / ALB / API Gateway) and the backend
process itself speaks HTTP.

## Trust boundary

- External clients must connect to the reverse proxy over **HTTPS**.
- Direct access to the Aegaeon service port is considered unsafe and should be blocked by network
  policy (security groups / firewall).
- Aegaeon treats inbound requests as untrusted until:
  1) the connection source is a trusted proxy, and
  2) forwarding headers assert `https` transport.

## What Aegaeon enforces

When TLS-proxy enforcement is enabled (default posture), Aegaeon performs the following checks:

1) **Trusted proxy source IP**
   - The request must come from an IP/CIDR listed in `AEGAEON_TRUSTED_PROXIES`.
2) **Forwarded transport must be HTTPS**
   - Either `Forwarded:` (RFC 7239) or `X-Forwarded-Proto:` must be present.
   - The extracted proto must be exactly `https`.
   - Forwarded chains are bounded by `AEGAEON_ALLOW_PROXY_CHAIN_LENGTH`; chains that exceed the
     configured length are rejected.
   - For multi-hop values, Aegaeon uses the nearest/rightmost hop entry when extracting `proto=`.
3) **Optional proxy mTLS fingerprint**
   - If `AEGAEON_REQUIRE_MTLS_FROM_PROXY=1`, Aegaeon requires `x-forwarded-client-cert` to include a
     valid SHA-256 fingerprint (and rejects embedded PEM).

Notes:

- Aegaeon does not parse `X-Forwarded-For` / `X-Forwarded-Host` for security decisions.
- Login, device-verification, management-login, and Federation public rate limits use the same
  trusted proxy boundary. When TLS-proxy enforcement is active and `Forwarded` contains a valid
  nearest-hop `for=` value, that value becomes the rate-limit subject. If only
  `X-Forwarded-Proto` is present, Aegaeon deliberately rate-limits the trusted proxy IP instead of
  trusting non-standard client-IP headers.
- The backend does not perform a TLS handshake itself in the typical reverse-proxy deployment.
- The strict transport boundary applies to all application routes except `/health`, including public
  protocol metadata endpoints and the authenticated management metrics endpoint.

## Failure behaviour

On rejection, Aegaeon returns JSON errors and also attaches a conservative RFC 6750-style challenge
header:

- `WWW-Authenticate: Bearer realm="aegaeon", error="tls_required"`

Status codes and reasons:

| Condition | Status | Error |
| --- | --- | --- |
| Missing remote address / untrusted proxy | `403` | `access_denied` |
| Missing forwarded headers | `400` | `invalid_request` |
| Malformed forwarded headers | `400` | `invalid_request` |
| `proto` is not `https` | `400` | `invalid_request` |
| mTLS fingerprint required but missing/invalid | `401` | `invalid_client` |

## Configuration surface (environment variables)

TLS-proxy enforcement is effectively enabled by default via the global policy gate:

- `AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY=1` (default) ⇒ forces TLS-proxy enforcement on.

| Variable | Default | Purpose |
| --- | --- | --- |
| `AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY` | `1` | Global policy gate. When enabled, forces TLS-proxy enforcement on. |
| `AEGAEON_TRUSTED_PROXIES` | `127.0.0.1,::1` | Comma-separated list of trusted proxy IPs/CIDRs. |
| `AEGAEON_REQUIRE_TLS_PROXY` | _unset_ | Explicit toggle for TLS-proxy enforcement. Set to `0` for local direct HTTP dev (but note the policy gate may force it back on). |
| `AEGAEON_ALLOW_PROXY_CHAIN_LENGTH` | `1` | Maximum accepted `Forwarded` / `X-Forwarded-Proto` hop count. Aegaeon uses the nearest/rightmost hop and rejects longer chains. |
| `AEGAEON_REQUIRE_MTLS_FROM_PROXY` | `0` | Require proxy-provided `x-forwarded-client-cert` SHA-256 fingerprint. |
| `AEGAEON_FORWARD_HEADER_LOG_VALUES` | `0` | Logs sanitized forwarding header values (debugging). |

`AEGAEON_ENFORCE_SECURE_PROTO` was removed. If it is present, startup fails closed; use
`AEGAEON_REQUIRE_TLS_PROXY` for the explicit transport-boundary toggle.

For the complete configuration list (including non-transport knobs), see:

- `docs/configurations/environment/README.md`

## Local development tips

If you run `aegaeon-server` directly on `127.0.0.1` without a reverse proxy, you have two options:

1) Disable the policy gate:
   - `AEGAEON_POLICY_REQUIRE_TRUSTED_PROXY=0`
2) Keep the policy on, but inject a forwarding header in your requests:
   - `X-Forwarded-Proto: https`

The load test harness (`crates/loadtest`) already sets a `Forwarded:` header for local runs.

## Testing & evidence

- Transport middleware tests:
  - `crates/server/tests/tls_enforcement_test.rs`
- Security suite hook:
  - `nix run .#security-suite` includes `cargo test -p aegaeon-server transport`

## Source references

- Transport enforcement: `crates/server/src/middleware/tls.rs`
- Rejection mapping / status codes: `crates/server/src/web/transport_boundary.rs`
