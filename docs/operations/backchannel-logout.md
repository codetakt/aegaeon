# Back-Channel Logout Tokens and delivery

Last updated: 2026-10-02

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
event and session/subject binding. Ordinary ID Tokens retain `typ: JWT`.

Each recipient receives a distinct random token `jti`. The existing logout event
identifier remains the logical event identifier in Aegaeon's session store. Tokens
include the issuer, recipient audience, `sid`, and empty
`http://schemas.openid.net/event/backchannel-logout` event object. They include
`sub` unless the recipient registration requires session-based logout, and never
contain `nonce`. Aegaeon stores the canonical signed token before sending it;
retries use exactly the same bytes, including `jti`, `iat`, `exp` and signature.

## Retained outcomes and bounded retries

Delivery state belongs to the retained logged-out session in the shared Redis
store. Aegaeon checks the event identity, associated client, current registration
and ownership before each send. A change to the issuer, registered URI or
session-based subject-release choice terminally suppresses delivery. Current
TLS, DNS and SSRF checks still apply. Successful recipients are not sent another
token for that event; other recipients retain independent outcomes. Local logout
effects remain independent of remote delivery success.

Only HTTP 200 and 204 acknowledge delivery. Other 2xx, redirects and permanent
refusals are terminal; redirects are not followed. Connection and timeout failures
and HTTP 408, 429, 500, 502, 503 and 504 can become eligible for a later retry.
There are at most three attempts, with at least five seconds after the first
recoverable failure and ten seconds after the second. A valid `Retry-After`
delta or HTTP date can increase that delay. Duplicate, malformed or overflowing
values, or a due time at or beyond the token/session horizon, end retry eligibility.

Retries are demand driven: a later invocation of the existing logout dispatch
path may send a due retry. There is no background scheduler or guarantee of
eventual delivery. The in-flight deadline is the earlier of the remaining
horizon and the claim time plus the configured HTTP timeout plus five seconds.
A lost owner can be replaced only after that deadline plus a further five-second
uncertainty delay. Stale preflight and completion operations cannot replace a
new owner's result. A matching owner can record a known acknowledgement after
its lease expires while the token and parent are still valid, unless another
operation has already terminalized the record. An expired preflight check changes
no state and permits no send. A lost response or failed outcome write can leave the remote
result unknown. A worker paused after its last ownership check can still send
late; these local leases do not establish remote exactly-once delivery or prevent
all overlapping requests. Relying parties must apply the protocol's replay rules.

No read, retry or takeover extends token expiration or the parent's original
retention deadline. Seconds remain exact integers in stored state. Production
Redis time supplies the state-transition clock; retry delays round fractional
seconds upward before adding their minimum interval. HTTP delta `Retry-After`
uses the same conservative rounding on the response clock. Fixed integer test
clocks do not round upward. Ownership checks retain the observed whole second,
so rounding a due time does not move the preflight clock into the future. All
due times must remain strictly before the original token/session horizon.

Dispatch reports distinguish actual sends, newly recorded acknowledgements,
already delivered recipients, deferred attempts, terminal failures, legacy or
missing state, storage failures and unknown outcomes. A prior acknowledgement
is not counted as a fresh delivery. A retained successful outcome remains known
after token expiration, until the original parent retention ends; it permits no
further send. Expired or missing parent history is not counted as success.

## Coordinated upgrade

The first logout of an active session records the delivery protocol version.
Already logged-out records without that marker have unknown delivery history:
Aegaeon suppresses their retransmission until their existing retention expires,
without asserting that their recipients logged out. It does not backfill history
or recreate state from an old event supplied by a caller.

Roll out all writers and serving instances together. Old instances can send
without observing the new delivery state, so mixed versions do not establish
these delivery guarantees. This is an additive Redis storage change with no
SQL migration or new environment setting; a database migration alone cannot
reconstruct historical outcomes. The runtime protocol is not represented by
the existing Kani session model; dispatch in that model configuration is
explicitly unavailable and sends nothing. Historical formal evidence does not
establish this implementation's full composition or product assurance.
