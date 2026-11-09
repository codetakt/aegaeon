# Membership discovery and interactive selection

Last updated: 2026-11-06

Status: draft

> **Status note:** Implementation candidate. Native acceptance and review remain in progress.

Owner: Engineering

Audience: implementers, security reviewers, integrators

Issue #319 adds a request-only selection profile and a separate self-membership
resource. Existing explicit single/multiple Organization grants and the selected
`/organizations/context` consumer retain their contracts.

## Registration and discovery

Register a domain target with `membershipDiscovery: true` and `management: false`.
Its audience must be an absolute URI. The client must have `organizations:discover`
in its OAuth scope registration and an active Organization client binding whose
entry for that exact discovery audience has precisely that permission. The same
binding explicitly lists the business audience and permitted business privileges.
The existing Organization client registration restrictions continue to apply and
are rechecked against current registration before issuance, discovery and selection.

Use authorization code with S256 PKCE and DPoP, `resource=<discovery audience>` and
`scope=organizations:discover` (optionally also `openid`). No Organization grant is
needed. These tokens last at most 300 seconds, have no business/exchange ceiling,
and cannot create a refresh token or act as a Token Exchange parent. `offline_access`
and business scopes are rejected with `invalid_scope`. An ID token, browser cookie, ordinary login token,
selected Organization token or management credential cannot call this resource.

`GET /organizations/memberships?audience=<business audience>` returns
`{"organizations":[{"identifier":"exact external ID"}],"next_cursor":null}`.
`HEAD` performs the same checks without a body. All responses are `no-store`.
Only the authenticated subject's active memberships with selectable current
privileges are returned. Empty pages are valid, including pages with a next cursor.
The subject-first partial index bounds each query to 25 memberships plus lookahead.
The cursor is a pagination hint bound to issuer/Environment/domain, subject identity,
client registration/binding, DPoP key, authentication time, audience, privilege query,
epoch and current policy/role snapshot. It grants no authority: every page rechecks
primary state and uses the authenticated subject in its database predicate.

## Browser selection

Opt in by advertising both existing Organization handlers and the additional type
in `policy.authorizationDetailsTypesSupported`. The exact wire shape is registered
in [the selection schema](../../../spec/organization-selection.schema.json):

```json
[{"type":"https://github.com/codetakt/aegaeon/spec/organization-selection/v1",
  "locations":["https://api.example/documents"],
  "privileges":["documents.read"],"selection":"interactive"}]
```

Direct authorize, PAR and JAR share the strict parser. There is one registered
business audience, a nonempty explicit privilege ceiling and no organization
wildcard. The current `prompt=consent`, `offline_access`, sender-bound lineage and
code requirements remain; this change does not add remembered consent (#325).
`prompt=none` cannot display a picker and returns the applicable interaction error.

The server stores the admitted request and its signed bytes unchanged. Its finite
selection continuation is bound to the browser session and current registration.
The form submits only a random transaction token and a choice index. Exact Origin,
session binding, a five-minute overall deadline and atomic single-use consumption
protect both pagination and selection. Membership incarnation, generation, role
versions and current permissions are rechecked before constructing the explicit
grant. The user then sees the exact Organization ID and effective privileges and
must separately approve them. A click in the picker grants nothing.

The resolved grant contains one Organization and only the intersection of the
requested ceiling, registered client permissions and current membership authority.
Before display, choices are checked against the explicit grant's 16 KiB encoded
limit, including JSON escaping of the identifier. Valid memberships whose resolved
grant exceeds that limit are skipped while preserving pagination progress; this
browser limit does not remove them from the membership discovery API.
Approval revalidates the original request, session and current authority. Code/root
issuance uses the existing Organization consent and lineage path. The original
selector remains in the server authorization snapshot; only the effective code
grant and token response contain `organization-grant/v1`. Unresolved selectors are
never resource credentials or refresh/token authority.

This is the type-specific comparison and consent transformation allowed by
[RFC 9396 sections 6.1 and 11.2](https://www.rfc-editor.org/rfc/rfc9396.html#section-6.1).
The token response reports the effective approved detail as required by
[section 7](https://www.rfc-editor.org/rfc/rfc9396.html#section-7).

## Producer and consumer contract

| Representation | Producer | Consumer and refusal boundary |
| --- | --- | --- |
| Request-only selector | Opted-in client, under the advertised RAR profile | Shared authorize/PAR/JAR parser; unknown profiles, mixed details, wildcard IDs and implicit privilege ceilings fail closed. |
| Selection continuation | Authenticated authorize flow, with the immutable admitted request and current membership page | Same-origin consent submission; current session, request, policy and epoch must still match before choosing. |
| Explicit approved grant | Separate approval of the chosen ID and effective subset | Existing code/root issuance and selected-token exchange; unresolved selectors never become access or refresh authority. |
| Discovery access token | Code/S256/DPoP flow, dedicated target and explicit client discovery permission | Membership endpoint only, with current primary authority and a fresh DPoP proof; business scopes, refresh and exchange are refused. |
| Domain target purpose | Authorized domain configuration | Live discovery/consent queries and version-three export/import; missing purpose is not inferred from an audience name. |

Metadata enables the selector explicitly; storing its name in an incoming request
does not activate a handler. Existing explicit-ID grant requests keep their own
validation and multiple-Organization semantics. The membership endpoint does not
accept a selected-context credential as discovery authority.

## Persistence and compatibility

The additive migration defaults all existing targets to ordinary business targets;
discovery remains disabled until explicitly registered. It forbids a target that is
both management and discovery, adds the subject-first index, and retains the checked
runtime privileges, protected function definitions and physical schema preflight.
Historical migrations remain unchanged.

Logical Organization snapshots use format 3 so a discovery purpose cannot be lost
when moving a domain. Version 2 transfer files must be restored using the matching
older implementation/database and then upgraded; version 3 readers refuse them
instead of guessing missing authority configuration. Restore/export and inactive
import projections all retain the new purpose. Deployment and rollback still require
matching binaries, migrations and retained stores as described in the database guide.

These source changes and functional tests do not discharge formal refinement,
provider qualification, performance or whole-product assurance obligations.
