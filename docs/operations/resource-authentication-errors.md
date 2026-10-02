# Protected-resource authentication errors

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Engineering

Audience: operators, API consumers, maintainers

Aegaeon applies the following response contract to `/resource`, enabled `/userinfo`,
`/application/authorization`, and `/oauth/upstream/refresh`. The first three support
GET and HEAD; UserInfo also supports POST, and upstream refresh supports POST.
Transport admission precedes this contract.

| Presentation or failure | Status | Challenge |
| --- | --- | --- |
| No credentials, blank Authorization, or unsupported scheme | 401, empty body | `Bearer realm="aegaeon"` |
| Bearer/DPoP without a token or with extra words | 400 `invalid_request` | Presented scheme |
| Duplicate or nontext Authorization | 400 `invalid_request` | Bearer |
| Admitted but invalid, expired, revoked, or unusable token | 401 `invalid_token` | Presented scheme |
| Insufficient scope | 403 `insufficient_scope` | Presented scheme |
| Missing, invalid, or replayed DPoP proof | 401 `invalid_dpop_proof` | DPoP |
| DPoP nonce required | 401 `use_dpop_nonce` | DPoP, exactly one `DPoP-Nonce` field |
| Internal or backend failure | Existing 500/503 response | None |

Each resource DPoP challenge includes `algs="EdDSA"`, matching the sole algorithm
accepted by the native proof verifier. A valid proof attached to Bearer credentials
does not change a later token or scope challenge to DPoP. Sender binding, audience,
authority and token validity checks remain required. These responses carry
`Cache-Control: no-store` and `Pragma: no-cache`.

[RFC 6750 sections 3 and 3.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-3) recommend omitting error details when authentication
is absent or unsupported. Aegaeon chooses an empty response body for that case.
[RFC 9449 sections 7.1 and 7.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-7) govern DPoP presentation, proof challenges and
algorithm advertisement. These envelopes also apply to OIDC UserInfo errors under
[OpenID Connect Core sections 5.3.1 and 5.3.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo).

## Request admission and proof effects

After transport and applicable URI/form admission, Aegaeon classifies the complete
credential presentation before proof validation, nonce handling and replay storage.
Absent, unsupported and structurally malformed credentials therefore neither consume
a proof nor issue or rotate a nonce. Once credentials are structurally admitted,
proof processing still precedes token validity and scope checks: those later
refusals can consume a valid proof. Use a fresh proof for a subsequent request.
Other routing and authority middleware can run before credential classification.

The existing case-insensitive two-word whitespace grammar is retained. A single
comma-containing field is not split into alternative credentials. Token validity
is evaluated separately; this contract does not introduce a token68 parser.

Aegaeon prohibits URI access-token transport as local policy. An `access_token`
query on a supported, matched resource method produces 400 `invalid_request` with
the unambiguous presented DPoP scheme, or Bearer otherwise. Percent-decoded
credential keys are inspected by the existing URI admission rules. Other URI
errors, unknown routes, unsupported methods and disabled UserInfo retain their
existing generic envelopes.

UserInfo POST continues to accept a body Bearer token in an
`application/x-www-form-urlencoded` request. Nonblank header and body credentials
cannot be combined. Effective blank body fields are omitted; duplicate fields,
content-type failures and form-extraction/body-limit failures receive 400
`invalid_request` with the applicable challenge. The form decoder retains its
existing percent-decoding behavior. A body token does not synthesize an
Authorization header for DPoP `ath` validation and cannot present a DPoP-bound token.
A header-authenticated empty POST still requires form content type in this version.

Invalid certificate metadata reaching a handler after credential admission receives
400 `invalid_request` with the presented scheme. The complete router's earlier
TLS/proxy certificate checks keep their existing ingress rejection contract.

## Validation scope

The focused router tests use isolated PostgreSQL configuration, authority and claims,
synthetically issued in-memory token records, native Ed25519 signatures and an
observable in-memory replay store. Nonce-effect tests use an owned Redis namespace,
comparing absent state, record bytes and remaining retention for an existing record
due for rotation. They compare the
same signed proof across early refusal, successful admission and replay refusal.
Later invalid-token and scope refusal controls observe replay consumption.
A per-instance key-manager fault maps to an internal error; the identical correctly
signed JWT with consistent stored metadata is accepted after the verifier recovers.
PostgreSQL claims/authority errors and a malformed owned Redis nonce record exercise
separate backend boundaries.

These finite tests do not establish all HTTP parser/proxy behavior, token-endpoint
issuance composition, production distributed replay behavior, or a complete upstream
provider refresh. Upstream positive controls stop after authentication at real link
lookup. Certificate handler tests distinguish direct invocation from router ingress.
HEAD checks cover the error envelope without asserting successful HEAD proof binding.
