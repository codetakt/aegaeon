# Client credentials target authorization

Last updated: 2026-09-30

Status: implementation contract

Owner: Identity

Audience: operators, OAuth client developers, verification reviewers

## Authority and request contract

Aegaeon authenticates each confidential OAuth client using that client's own
registered credentials. The access token retains that client as `client_id` and
subject. Its audience identifies the selected resource, independently of the
client's identity. Authentication alone grants no target or scope authority.
The client registration and active OAuth profile must also permit
`client_credentials` (RFC 6749 section 4.4).

Configure `policy.clientCredentials` through the existing versioned management
policy API and activate it. The default policy grants no new client-credentials
issuance. There is no environment-variable override. Canonical audiences and
exact URI aliases are defined once, in `policy.tokenExchange.targets`.
Client-credentials rules and token-exchange rules grant independent authority;
permission for one grant does not authorize the other.

```json
{
  "tokenExchange": {
    "version": 1,
    "targets": [{
      "audience": "orders-api",
      "resourceAliases": ["https://orders.example/api"]
    }],
    "rules": []
  },
  "clientCredentials": {
    "version": 1,
    "resourceServers": [{
      "targetAudience": "orders-api",
      "introspectionClients": ["orders-resource-server"]
    }],
    "rules": [{
      "clientId": "orders-worker",
      "targetAudience": "orders-api",
      "scopes": ["orders.read", "orders.write"],
      "defaultScopes": ["orders.read"],
      "defaultTarget": true
    }]
  }
}
```

A request may select `audience=orders-api` or
`resource=https://orders.example/api`. `audience` is Aegaeon's logical target
selection extension; `resource` follows the absolute-URI form in RFC 8707
section 2. Both selectors use the same catalog and caller-to-target rule.
One of each may be supplied only if both resolve to the same target. Repeating
either selector, even with the same value, returns `invalid_target`, as do
unknown, conflicting or unauthorized selections. These single-target limits
are Aegaeon profile restrictions. They do not change other grants' selectors.

An omitted selector requires a rule explicitly marked `defaultTarget: true`.
There is at most one default per caller. There is no implicit client-ID audience
or first-rule selection. Explicit requested scopes must be nonempty and fit
both the selected rule and the current client registration. An omitted `scope`
uses the rule's explicit `defaultScopes`, which must also fit both ceilings;
empty defaults or invalid scopes return `invalid_scope`. The scopes `openid`
and `offline_access` are not supported in these rules. No refresh token is
issued by this grant.

Policy version 1 permits at most 64 resource-server bindings, 256 caller/target
rules, and 128 scopes or introspection clients per entry. Identifiers are
nonempty, contain no whitespace/control characters, and have a 1,024-byte bound;
scope tokens have a 256-byte bound. Duplicate targets, caller/target pairs,
introspection clients, scopes and defaults are rejected. Defaults must be a
subset of the rule's scopes. Every rule target requires an explicit
`resourceServers` entry; an empty `introspectionClients` array grants no
independent resource-server visibility. Referenced targets must exist in the
shared catalog. Every client-credentials policy change uses the existing
security-change acknowledgement and reason, including removal of authority.

## Stored authority and online checks

Issuance records a versioned authorization snapshot binding issuer, environment,
configuration provenance, caller registration identity, selected audience,
issued scopes, selected policy context and introspection-client identities.
When issuing application claims, the existing application publication guard
compares its locked client registration UUID with the caller UUID captured in
this authorization before minting. Recreating a client with the same identifier
cannot attach the replacement registration's application claims to the old
authorization. This check shares the existing transaction; it introduces no
new client-credentials publication lock.

The access-token record carries the snapshot's SHA-256 fingerprint. The marker
and snapshot must both exist and agree; missing or mismatched metadata cannot
fall through to legacy validation or owner visibility. Origin is never inferred
from a token's subject or from current configuration.

Introspection (RFC 7662 sections 2.1 and 2.2) validates this authority before any
visibility shortcut. The issuing caller may introspect its currently valid
token. A separately authenticated resource server must satisfy both the
captured and current explicit introspection binding, current registration
membership, and the existing endpoint authentication/profile requirements.
An audience equal to an introspecting client ID does not grant visibility.

Online validation also checks the current caller identity and membership,
client-credentials eligibility, registration scope ceiling and selected policy
context. Changing the selected rule, target aliases or introspection binding
invalidates the captured context. Unrelated configuration changes may preserve
it. Backend failures fail closed through the existing operational-error path;
stale or invalid authority yields an inactive or invalid token. Aegaeon's online
resource endpoint and token-exchange source validation apply the same checks.

Same-audience exchange preserves the client-credentials snapshot, caller,
audience and immutable provenance while attenuating scopes and expiry. Atomic
store publication rejects restriction removal, caller substitution, widened
scopes, new cross-target exchange authority or refresh escape. A change to only
`clientCredentials` does not change the existing token-exchange policy digest.

## Activation, migration and compatibility

Requests use the existing configuration admission boundary. Relevant client
identities and authentication material are pinned before authentication, then
checked against the admitted database revision and projection fingerprint.
Drift returns the existing 503 response. A request admitted under a runtime
snapshot may finish under that snapshot when these checks still agree; admission
alone does not promise completion. Activation causes a
stale runtime to reject subsequent admissions with the existing 503/restart
behavior. This feature does not add a publication-time lock or immediate
cross-store revocation guarantee. After reload, online validation uses the
current selected context. Offline JWT verification cannot observe current
policy removal; its limit is token expiry and the consumer's own online-check
or revocation strategy.

Apply the schema migration, prepare explicit catalog entries, rules, defaults
and resource-server bindings, activate the configuration, and coordinate the
upgrade of all issuer runtime processes. A mixed deployment with old writers
does not enforce the new contract. Existing unmarked tokens retain their prior
semantics and gain no new resource-server introspection permission. Revoke them
or drain the maximum outstanding access-token lifetime before treating the
whole deployed population as covered. Do not backfill their authority.

Rust callers of the client-credentials issuer APIs must supply the typed,
request-bound `AuthorizedClientCredentials` permit produced by authorization.
Raw client-ID/resource minting overloads are removed. The permit has no public
unchecked constructor or deserializer. This boundary concerns authenticated
grant issuance; it does not turn a trusted low-level signing capability into an
untrusted interface.

The synchronous `TokenValidator::introspect_token` convenience API returns
inactive whenever either client-credentials authority marker is present. It has
no live environment-authority context. Use authenticated HTTP introspection for
these tokens. Signature and stored-metadata validation alone does not establish
current policy or registration authority; Aegaeon's online handlers additionally
perform the currentness checks described above.

## Verification boundary

This contract concerns Aegaeon's client-credentials issuance and online token
handling. It does not extend the client-credentials policy to unrelated grants
or establish downstream resource-server behavior. Existing abstract
introspection, resource-indicator and token models do not establish this new
policy, persistence or runtime correspondence. Local regression results and
formal obligation discharge are distinct. Formal verification requires a new
source-bound evaluation of the changed target, identity, scope, storage,
activation and composition obligations.
