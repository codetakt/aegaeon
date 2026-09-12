# Token exchange targets

Last updated: 2026-09-12

Status: current implementation baseline

Assurance: formal correspondence remains partial

Owner: Identity

Audience: operators, application developers, verification reviewers

## Request contract

Aegaeon accepts RFC 8693 form requests at the discovered `token_endpoint`.
The client must authenticate using its registered token endpoint method and be
allowed to use `urn:ietf:params:oauth:grant-type:token-exchange` by both its
registration and active OAuth profile. Enable the grant in the active management
policy's `allowedGrantTypes` as well.

The initial profile accepts locally issued access tokens as `subject_token` and
issues access tokens. It does not support actor tokens, delegation, refresh-token
exchange outputs, or a private JSON exchange endpoint.

`audience` names a registered logical target. `resource` names an exact registered
absolute URI without a fragment; queries are allowed. Repeated parameters and
both kinds of selector may identify the same target. Unknown selectors and
requests naming distinct targets return `invalid_target`. These are profile
restrictions, not a claim that RFC 8693 prohibits multiple target services.

Legacy same-audience exchange requires a nonempty explicit `audience` matching
the subject's audience. Omitting it, or supplying only `resource`, returns
`invalid_target`; the client ID is not used as an implicit target. This is an
Aegaeon restriction: RFC 8693 section 2.1 marks these selectors as optional.

Successful responses include `access_token`, `issued_token_type`, `token_type`,
`expires_in`, and the actual target `scope`. DPoP-bound output uses `DPoP` as its
token type; other output uses `Bearer`. Authorization-code and refresh responses
use the confirmation of the issued token as well (RFC 9449 section 5). The subject
is not consumed by exchange. Code responses report the issued lifetime even when
an earlier authorization horizon caps a subsequently increased configured TTL.

## Management policy

Configure `tokenExchange` through the existing versioned management policy API,
then activate the configuration. It is stored in `environment_policies`; there
is no environment-variable override. The default is version 1 with empty
`targets` and `rules`, which grants no authority to change audience.

For example, an issuer can authorize an application to exchange an existing
`orders` permission for a target-specific `orders.read` permission:

```json
{
  "tokenExchange": {
    "version": 1,
    "targets": [
      {
        "audience": "orders-api",
        "resourceAliases": ["https://orders.example/api"]
      }
    ],
    "rules": [
      {
        "clientId": "orders-web",
        "sourceAudience": "https://id.example/userinfo",
        "targetAudience": "orders-api",
        "scopes": [
          {"targetScope": "orders.read", "sourceScopes": ["orders"]}
        ],
        "defaultScopes": ["orders.read"]
      }
    ]
  }
}
```

All source conditions for a mapping must hold. Each target scope also must be in
the client's allowed scopes. If the request omits `scope`, the rule's explicit
defaults apply; absent or unauthorized defaults cause rejection. Scope spelling
alone does not establish equivalent permission at different APIs. OIDC scopes do
not automatically authorize an application resource.

The policy accepts at most 64 targets, 256 rules, and 128 scope mappings per rule.
Names, aliases, routes and scopes must be unambiguous and bounded. Unknown object
fields, fragments, duplicate values, and empty source conditions are rejected.
Changing a nonempty exchange policy requires the existing security-change
acknowledgement and reason. `retainRefreshChain` must remain enabled.

## Original authorization and narrowing

Exchange authority is captured when an authorization code is created, binding
issuer, client, subject, exact policy digest and target permissions. Initial
support requires an offline grant with an active refresh parent. Historical
records without this snapshot cannot acquire authority under a newer policy;
they retain only the existing same-audience exchange behavior. Policy changes
require a new authorization before snapshot-based exchange can continue.

If code redemption does not issue a refresh token, the access token receives
neither the captured target authority nor its revocation root. This includes
grants without `offline_access` and clients whose refresh issuance is disabled.
Such tokens can use only explicit same-audience exchange; adding a target policy
later does not grant them permission to change audience.

A refresh token retains its original grant. A narrowed refreshed access token
receives only the exchange permissions whose original source conditions still
hold. Exchanging that token cannot restore omitted permissions. Exchange output
retains only its selected target and scopes, so further exchange can narrow at
that target when a corresponding same-target rule exists; it cannot move on to
a third target or regain dropped scopes.

## Binding, lifetime and revocation

Exchange preserves the subject and sender binding. The minting time is read
after awaited audit work, and the output's absolute expiry cannot exceed the
subject's expiry. Every exchange-authorized token also retains an internal
revocation root and absolute horizon. The horizon uses checked arithmetic at
authorization; later refreshes remain bounded by it even if configured token
lifetimes increase. The root is stored in token records and grant metadata; it
is not included in JWT claims or OAuth responses.

Refresh revocation and refresh reuse record root denial before bounded child
cleanup. Denial remains effective if cleanup exceeds its budget or an older
writer loses a child-index entry. Online access-token and refresh-token checks
consult the root, and exchange and refresh publication check it atomically in
Redis. Exchange publication also fences the mutation lease and retained input
records. This subject recheck also applies to legacy same-audience exchanges,
including grants without a refresh parent. Expired, revoked or concurrently changed
subjects return `invalid_request` without publishing a token. Lost operation leases,
unavailable storage and invalid index state remain server errors. These revocation
semantics are the Aegaeon profile; RFC 8693 does not universally mandate them.
Cleanup failures still report a storage error even when root denial
has already taken effect.

Apply the schema migration and replace all issuer runtime processes before
enabling target policy. Older runtimes do not consult the root marker, so a mixed
version deployment cannot enforce this revocation guarantee. This guarantee concerns
the updated runtime's online token-store checks and introspection. Applications
that validate JWTs offline need a separate revocation strategy; they cannot infer
immediate server-side denial from an otherwise unexpired JWT.

## Claim release and evidence boundary

Snapshot-based exchange issues only issuer-controlled standard access-token
claims. It does not copy arbitrary user attributes or broker claim-release
policies to the new audience. Subjects carrying `authorization_details` are
rejected, including same-target exchanges, until a target-aware translation is
available. Organization hints do not grant membership. Application-specific
claims and their release policy are a separate feature.

The F* model checks abstract target authority, attenuation, binding, deadlines
and monotone root denial. The Tamarin model checks a fixed read-only exchange
and online-use trace with abstract client/sender authentication. They do not
establish Rust/serde/Redis implementation correspondence, cryptographic
correctness, or application authorization. The affected compliance claims remain
partial. Regression tests cover the standard HTTP contract, real Redis commits,
revocation races, lost child indexes and cleanup failure. PostgreSQL/Redis composition
tests cover policy reload, unchanged-policy authority, no authority backfill and
foreign-environment rejection. Consent-route regressions repeat fresh code redemption
and refresh with two, three and nested custom claims. Their authenticated sessions
are fixtures; deployed authorization flows and process restart still require
E2E acceptance.
