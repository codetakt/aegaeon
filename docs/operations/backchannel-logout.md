# Back-Channel Logout Token profile

Last updated: 2026-10-03

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers, relying party implementers

## Issuance and recipient compatibility

When back-channel logout is enabled, Aegaeon sends a signed Logout Token to each
registered relying party's back-channel logout URI as the `logout_token` form
parameter. The token uses the active OIDC ID Token signing key, `RS256`, and its
published `kid`, for both local RSA and AWS KMS signing.

Logout Tokens carry `typ: logout+jwt` and an `exp` exactly 300 seconds after
`iat`. Aegaeon captures the issuance clock once and refuses issuance if the time
is before the Unix epoch, exceeds the supported signed NumericDate range, or
cannot accommodate the five-minute lifetime. This lifetime is a local issuance
policy, independent of ID Token lifetimes and logout-session retention; there is
no separate environment setting.

[OpenID Connect Back-Channel Logout 1.0 incorporating errata set 1,
§§2.4, 2.6 and 4.1](https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken)
requires `exp` and recommends explicit typing. Aegaeon adopts that recommendation.
The five-minute duration is not mandated by the specification. On upgrade, relying
parties that previously accepted only `typ: JWT` for Logout Tokens must accept
`logout+jwt` and validate expiration along with the signature, issuer, audience,
event and session/subject binding. Ordinary ID Tokens retain `typ: JWT`. Aegaeon's
`id_token_hint` consumer rejects `logout+jwt` and `application/logout+jwt`
case-insensitively. After signature verification and duplicate-safe claim decoding,
it also rejects the back-channel logout event key, including in tokens with
`typ: JWT` or no type. Ordinary ID Tokens remain accepted with an absent or
standard type.

Tokens preserve the existing logout event's `jti`, issuer, recipient audience,
`sid`, and empty `http://schemas.openid.net/event/backchannel-logout` event object.
They include `sub` unless the recipient registration requires session-based logout.
They never contain `nonce`. A renewed signature or issuance timestamp does not
make a retransmission a new logical logout event for replay handling.

## Delivery and upgrade scope

Delivery remains best effort, with the configured per-recipient timeout and
existing URI checks. This profile correction does not establish reliable retry,
fan-out consistency or recipient idempotency. Local logout effects and stable
event identifier ownership retain their existing behavior. No database migration
is required.
