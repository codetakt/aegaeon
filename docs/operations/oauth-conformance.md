# OAuth sender binding and unsupported authorization details

Last updated: 2026-09-11

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## DPoP responses

RFC 9449 §§5, 7.1 and 9 distinguish authorization-server and resource-server
responses. The token endpoint returns `400 invalid_dpop_proof` for malformed,
invalid or replayed proofs, and `400 use_dpop_nonce` with `DPoP-Nonce` for nonce
challenges. Resource endpoints return 401 with a DPoP `WWW-Authenticate`
challenge. Their nonce challenges also include `DPoP-Nonce`.

Empty proof identifiers are refused before nonce/replay-store access. Valid
identifiers still undergo replay detection; the server does not claim to infer
the randomness of a client-generated identifier.

Nonce records are scoped separately to the AS and RS within each runtime
namespace. Clients must keep separate nonce state for each issuer and role.
After upgrading, previously issued nonce values may receive a new challenge;
retry with a fresh proof and the nonce from the applicable endpoint. Backend
failures return 503 without misclassifying them as invalid credentials.

A DPoP-bound token presented with Bearer authentication is rejected even when
the request also includes a valid proof. A Bearer `invalid_token` challenge for
that attempted scheme is consistent with RFC 9449 §7.2. Certificate-bound
tokens use Bearer authentication with `cnf.x5t#S256`, as specified by RFC 8705.
The scheme check also applies to the upstream-refresh resource. UserInfo GET
and POST preserve the attempted scheme in the challenge even when a proof is
present. A DPoP scheme without its proof returns `invalid_dpop_proof` for every
header separator accepted by the resource parser.

Device-code responses and saved access-token records use the confirmation
actually issued: `DPoP` for `cnf.jkt`, and `Bearer` for certificate-bound or
unbound tokens. Clients must use the returned scheme when presenting the token.

## Mixed DPoP and certificate-bound clients

Keep the environment's DPoP default and nonce enforcement. Enable `mtlsEnabled`
and select `senderConstrained: MTLS` on an administrative OAuth profile for
clients that use certificate binding. Other profiles continue to use DPoP.
Disabling the refresh-policy option cannot remove a binding from an already
bound refresh token. Such tokens always require the original key or certificate.
Setting a profile to NONE does not remove an environment binding requirement.
DPoP and mTLS are alternative mechanisms; a resource checks the binding stored
in each token, independently of the default selected for new issuance.

Terminate TLS at a trusted proxy that verifies client certificates, removes all
client-supplied certificate forwarding headers, and forwards only the verified
certificate's SHA-256 fingerprint. Configure an explicit trusted proxy range
and HTTPS enforcement. A client-supplied header or an untrusted direct
connection is not certificate evidence.

An environment's mTLS token policy no longer enables certificate requirements
for browser login, consent and management routes. Operators who require client
certificates on every ingress request must explicitly set
`AEGAEON_REQUIRE_MTLS_FROM_PROXY=1`. That transport policy remains enforced.
Separate mTLS endpoint aliases/hosts can require certificates during the TLS
handshake while the browser-facing listener permits ordinary HTTPS. A failed
TLS handshake has no OAuth HTTP error response. When an HTTP resource request
reaches the server without the certificate required for its token, it receives
401 `invalid_token`.

This profile support implements certificate-bound tokens, not OAuth
`tls_client_auth` or `self_signed_tls_client_auth`. Those authentication methods
and mTLS DCR admission remain unsupported and are rejected. DCR's standard
`tls_client_certificate_bound_access_tokens` flag denotes mTLS specifically;
it is not an alias for generic sender binding or DPoP. Management-created mTLS
clients use a supported client authentication method in addition to binding.

## RAR support boundary and upgrades

No runtime RAR type currently implements semantic validation, attenuation and
resource authorization. A type name alone cannot enable these semantics.
Activation and startup reject nonempty `authorizationDetailsTypesSupported`.
The token endpoint rejects nonempty `authorization_details` with 400
`invalid_authorization_details` before consuming a code, rotating a refresh
token or publishing access tokens. Duplicates return `invalid_request`, even
if both values are empty. A single empty form value is omitted per RFC 6749
§3.2; unknown unrelated OAuth extensions remain ignored.

Stored RAR-bearing codes and refresh grants are rejected with `invalid_grant`
before consumption or rotation. Exchange refuses such subjects with
`invalid_request`, including legacy same-audience exchange. Resources reject
stored details they cannot enforce with `invalid_token`. Existing constraints
are retained in storage; clients must obtain new authorization after their
intended permissions can be expressed by supported mechanisms. Removing the
request parameter cannot remove constraints from an existing grant.

Before upgrading an environment with a nonempty type allowlist, remove that
allowlist through the old binary's management API using an audited
configuration activation. Coordinate clients relying on RAR: new constrained
requests will be refused. Keep the prior binary and configuration evidence
for rollback planning; do not modify the migration ledger or silently erase
constraints from tokens. The protocol-only repair did not change migrations.

The RAR matrix remains partial: structural models and persistence tests do not
establish full endpoint conformance or type-specific authorization. Internal
tests of fabricated stored details do not prove such subjects are issuable
over supported HTTP endpoints.

## Authorization diagnostics

Consent errors return the general description `consent request could not be validated; restart authorization`.
Missing Origin does not assert that a stored transaction is expired or already used.
Each consent submission receives a server-generated `x-request-id`; structured warning events carry
that identifier and a stable reason for Origin, session, snapshot, or transaction admission failures.
Storage failures remain `503 temporarily_unavailable`. Authorization-code refusals log a stable
reason including `state_reused` or `nonce_reused` with the authorization request identifier.
Events do not include raw state, nonce, code, consent token, Request Object, or database payloads.
The public OAuth error categories and redirect validation remain unchanged.
