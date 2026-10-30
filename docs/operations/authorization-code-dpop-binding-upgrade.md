# Authorization-code DPoP binding and coordinated upgrade

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

Aegaeon accepts `dpop_jkt` on direct authorization GET/POST and plain PAR forms
(RFC 9449 sections 10 and 10.1). It must be the canonical, unpadded base64url
encoding of a SHA-256 JWK thumbprint: 43 ASCII characters representing 32 bytes.
Whitespace, padding, URI prefixes and noncanonical final bits are rejected.
Percent decoding precedes duplicate-name checks. Empty form values are omitted;
multiple remaining values are rejected. Signed empty, null and non-string
claims are invalid.

With a direct signed or encrypted Request Object, Aegaeon uses the verified
RFC 9101 parameter set. Only the inner `dpop_jkt` establishes a key. One outer
copy is ignored, including when different, malformed as a thumbprint, or absent
from the signed object. This is the advertised JAR behavior; it does not adopt
the older OIDC Core outer/inner parameter assembly as a second authority.
Normal syntax, singleton and client-ID rules still apply. At PAR, authorization
parameters belong inside the Request Object (RFC 9126 section 3): a nonempty
outer body `dpop_jkt` is rejected even when equal.

PAR also accepts a DPoP header, verified for POST and the PAR URI with the
native verifier and authorization-server nonce/replay policy. Parameter only,
header only and matching both mechanisms are supported. For a pushed JAR,
a valid header can supply a key absent from the signed claims. Signature and
client-authentication keys may differ from the DPoP key. The later
`request_uri`, login, consent, reauthentication and step-up retain the accepted
key and original Request Object bytes. An outer parameter cannot replace the
stored key or supply one to an unbound stored request. A direct `/authorize`
DPoP header remains ignored.

PAR captures the selected client registration and authentication material once
and uses that snapshot for authentication, client-associated JAR keys, scopes,
redirects and grants. Private-JWT client selection alone is not authentication.
Remote-key and replay state remain shared. Profile selection is a later SQL
observation; this is not a global configuration transaction. Front-channel
requests and continuations recheck current client/profile policy, which may
reject a previously pushed request without changing its accepted key.

The token endpoint requires a fresh proof for a bound code even if the client
minimum is false, its current profile has no sender constraint, or refresh
binding enforcement is disabled. Missing/invalid/replayed proofs return HTTP
400 `invalid_dpop_proof`; a valid proof for another key or an mTLS substitution
returns HTTP 400 `invalid_grant`. Existing invalid-client and incompatible
mTLS-policy precedence remains. Nonce challenges use `use_dpop_nonce` and
`DPoP-Nonce`; unavailable protection backends return HTTP 503
`temporarily_unavailable`. A valid DPoP proof may have spent its jti before a
later rejection. The code remains available on preflight/key rejection and
requires a fresh proof for retry.

Both synchronous and asynchronous library APIs enforce the stored code key
before signing, descendant creation and the original-payload compare-and-consume.
The `bound` library APIs are a trusted caller boundary: their sender context
must come from independently verified possession for that token request. A
`cnf` or an expected key does not attest possession. Convenience APIs with no
verified sender cannot redeem a bound code. Confirmation must agree with the
verified sender. Existing stronger refresh/lineage/revocation constraints remain.

PAR resolves JAR replay admission only after effective parameters, the selected
client, the later profile and DPoP agreement pass. It then admits the JAR jti
once immediately before persistence. Failure to persist or a lost reply does
not restore the jti; retry may need a new Request Object and DPoP proof. Pushed
JAR is not spent again at authorization. Direct JAR retains its code-publication
commit context. DPoP replay, JAR replay, PAR reservation and code consumption
are distinct stores; no cross-store rollback is promised. Physical Redis faults
after destructive commands and lost successful replies can leave uncertain
commit outcomes. Do not restore an old code to manufacture a retry.

## Deployment

This release changes PAR and authorization-code namespace/digest versions to
v3, requires explicit version 3 and `dpop_jkt` in stored code/PAR envelopes,
uses authorization snapshot version 3, and revises the step-up digest domain.
An explicitly null key means admitted unbound; a missing field is rejected.
Code/state/nonce/index/lease/placeholder keys and PAR Lua arguments use the
coordinated versions and the existing authorization-code-grant Redis hash group.
Old PAR v1/v2, code v2 and unversioned/v2 continuations require fresh interaction.
No legacy record is inferred to be bound or backfilled from current client policy.

1. Stop or drain all old `/authorize`, `/par`, continuation/consent/login/step-up
   writers and `/token` code readers on every instance. Stop ingress before
   switching readers or writers. Namespace isolation alone cannot stop a live
   old authorization endpoint from ignoring `dpop_jkt`.
2. Account for pending-flow loss. Existing pending codes, pushed requests and
   browser interactions are abandoned; clients restart authorization and push
   new requests where applicable. Keep the old entries under their existing
   TTLs for diagnosis; never copy them into v3 or rewrite null/missing keys.
3. Deploy the coordinated version to all roles, verify the intended runtime
   configuration and shared-store endpoints, then resume traffic. Execute the
   operational restart and fresh-flow checks for the actual fleet. Local decoder
   and integration tests do not establish mixed-fleet or deployed-system safety.
4. For rollback, stop writers/readers again and drain/invalidate new pending
   interactions before resuming. Only a reviewed rollback version preserving
   client-minimum, sender-binding, replay and lineage contracts is eligible.
   Do not resume unsafe older readers or translate v3 authority into old records.

Do not clear DPoP replay/nonce or grant-lineage stores during rollout or rollback.
Existing issued access/refresh tokens retain their previous compatibility and
protection contracts; this change does not revoke all issued tokens. No new
runtime environment setting or PostgreSQL schema migration is required.
