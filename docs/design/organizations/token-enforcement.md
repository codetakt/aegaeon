# Selected Organizations token enforcement

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, security reviewers, resource server integrators

## Authority contract

This refines ORG-R03/R06/R07/R08/R09/R10/R21/R22/R23, ORG-G01/G05/G06/G07/G11/G14
and ORG-P01/P02/P03/P04/P08/P12/P13/P14. Implementation and test evidence do not
discharge these composite obligations. The original approved grant and its
selected organization credential remain different public types.

The selected token requires its original server-side root ceiling, an
independently authenticated issuer/client/registration/subject/key binding,
exactly one target and one organization-access detail. Require explicit feature
activation, confidential DPoP client, active retained refresh lineage, current
client/target scope policy and a permitted signed JWT issuer. The initial
Organizations profile requires RS256. This is a profile constraint, separate
from the RFC 9068 requirement to support RS256. Never infer a grant from public
RAR JSON, a legacy login token, a client ID, an operator session or a role name.
Actor tokens, ID tokens, service tokens and organization-token chaining are
refused in this profile. Parent grant tokens cannot be used as selected access.

The primary transaction locks active Environment/topology before domain, then
selected client, organization and membership/user authority in the established
order. It explicitly refuses PostgreSQL recovery/read-only suppliers. Compare
current domain and client-binding revisions with the original grant, require the
same live client registration and exact public ID, and resolve the opaque
external organization identifier inside the exact target domain. The native
selector intersects requested privileges with original approval, current
membership/roles and current client target policy. Empty authority is refused.
Only the selected organization's membership is checked: revoking another
organization membership must not invalidate an unrelated selection.

Selected metadata retains the native decision, domain revision and explicit
client-binding UUID/revision. The private original ceiling remains bound to its
original root. Before any positive use, validate the private snapshot against
the original ceiling and public signed token, then recheck current primary
state. Missing or inconsistent snapshots do not acquire defaults. Terminal
revision values cannot issue new authority. Current role, membership incarnation,
generation, revision, subject ownership and exact external identifier remain
mandatory; newly granted authority requires new original approval.

Native repository methods own no token authentication. Their callers must
establish signature, sender possession, audience, original grant/root liveness
and authenticated registration correspondence. The web boundary owns finite
admission, SQL timeouts, transaction cleanup, response deadline and commit.
No production endpoint may replace these preconditions with a caller flag.

## Protocol and publication

Keep existing RFC 8693 source-token, target and scope policy checks. Invalid
source uses `invalid_request`; unavailable target uses `invalid_target`;
malformed or expanding structured detail uses `invalid_authorization_details`;
scope expansion uses `invalid_scope`. Authentication and DPoP errors retain their
own contracts. Authority-store failure is an explicit service error and does
not disclose membership existence.

Mint a DPoP-bound `at+jwt` for one exact audience, with expiry no later than
300 seconds, configured access-token TTL, source expiry or original root horizon. Preserve original
`auth_time`, `acr` and any supported original authentication-method evidence.
Do not issue a selected organization refresh token. Token response, signed JWT
and authorized introspection carry the same external identifier, nonempty
privileges and access basis. Verify signed claim correspondence with stored
metadata, including client ID, confirmation key and authentication time, before
accepting a selected credential. The atomic token store independently rejects
changed authentication context, selected privilege expansion, client-binding
changes and an output horizon beyond its source. Offline introspection helpers
return inactive for structured organization authority. Private UUID bindings do not replace the public
external identifier in authorization details.

Retain the existing token/root publication guard and recheck primary authority
after publication before returning the token. A concurrent cancellation may
leave an undelivered or already inactive token; it cannot authorize a subsequent
online operation. There is no PostgreSQL/Redis atomic-commit assumption. Checks
started after a successful cancellation response must reject affected old
credentials. Already admitted external business I/O may finish.

## Introspection and own resource server

Both JSON and signed introspection authenticate the recipient and require the
explicit current target registration defined by
[introspection recipients](introspection-recipients.md). Bind the request's
pinned authentication projection fingerprint to the primary runtime projection
before accepting the resolved registration UUID. This prevents a public ID
recreated during authentication from borrowing old credential validation.
The token holder and audience-string equality provide no recipient bypass.
Return inactive for noncurrent or unauthorized tokens and explicit failure for
unavailable authority. No positive cache or offline fallback is allowed.

Introspection supplies `cnf.jkt`; the resource server separately verifies the
presenting application's DPoP signature, key, `ath`, method, URI, nonce/time and
replay. Aegaeon's own delegated Organizations API must use the same current-state
checker and complete resource authentication before admission. Generic legacy
resource validation continues to refuse unsupported RAR tokens unless a complete
Organizations checker is present. Operator management authentication remains a
separate capability and cannot replace selected membership authorization.

## Enablement and evidence

Public RAR configuration and discovery remain disabled until the complete
original consent, selected mint, introspection and own-resource paths exist and
pass integrated security tests. Restore epoch protection, invitation workflows,
admin grants and export/import remain separate required shipment work.

Required regressions include actual HTTP consent/code/refresh/exchange, original
ceiling omission/tampering, unrelated-organization continuity, client or recipient
re-registration, JWT/response mismatch, signature algorithms, DPoP substitution
and replay, role expansion/rejoin, concurrent mint/cancel, current primary faults,
store outage and recovery, and actual guard-removal negative controls. Check the
same source/artifact and migration catalog used by the running tests.

Normative protocol boundaries: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html),
[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html),
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html),
[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html), and
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html). The exact type, bounds,
online-only profile and registration bindings above are Aegaeon policy.
