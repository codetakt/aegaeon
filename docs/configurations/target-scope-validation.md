# Target rule scope validation

Last updated: 2026-10-01

Status: current implementation baseline

Owner: Identity

Audience: operators, OAuth client developers, verification reviewers

Target rules must fit the issuing OAuth client's registered `allowedScopes`.
This applies to every `tokenExchange.rules[].scopes[].targetScope` and every
`clientCredentials.rules[].scopes` entry, including entries outside defaults.
Target audience and client identity remain independent; URI audiences are valid.
RFC 8707 permits mapping a resource URI to a different canonical audience.

Policy PATCH validates the complete resulting policy. It checks active client
memberships in the current configuration, which are carried into the next
version. Creating a configuration document checks the same current memberships;
activation repeats the check because clients may have changed since creation.
An absent, retired, deleted or historical client cannot supply a scope ceiling.
Expired ACTIVE membership is checked too; passing does not restore eligibility.
Register callers before saving their rules.

Client creation and updates check rules referring to that client against the
candidate scopes. DCR persistence uses the same check before rotating registration
access tokens or secrets. All checks execute under the existing environment row
lock in the transaction that saves the mutation. They do not use the runtime
registry cache. Deleting a client still revokes access and may leave dormant
rules; remove those rules before the next policy write. Drafts do not reserve
client scopes, so a valid draft can become ineligible for activation later.

Management errors return HTTP 400 `invalid_request`, with the first violation in
`message` and every violation in `details.scopeViolations`. Each item identifies
the zero-based rule index, client ID, target audience, offending scope and reason.
DCR returns HTTP 400 `invalid_client_metadata` with the affected rules and scopes.
No part of the rejected configuration, client mutation or credential rotation is
saved. Runtime capture, current-client ceilings, policy-digest and lineage checks
remain necessary and unchanged; token requests never partially grant invalid scopes.

## Upgrade procedure

1. Before enabling the new writers, inventory **all environments and all rules**
   using a database role with read access to the three referenced tables:
   `psql -X -v ON_ERROR_STOP=1 -f scripts/operations/check_target_scope_ceilings.sql`.
   Supply connection credentials through the normal PostgreSQL service/password
   mechanism. The script uses a repeatable-read, read-only transaction, prints
   every violation as JSON, and exits nonzero when any are found.
2. Review each reported rule/client/scope. Through the management API, remove or
   correct the complete rule collection, or expand the client's allowed scopes
   only when that permission is intended. Register intended missing clients first.
   Do not widen authority merely to pass validation. `tokenExchange` and
   `clientCredentials` objects supplied to PATCH replace those objects; omitted
   policy fields retain their current values.
3. Repeat the dry-run until `violationCount` is **0**. Unrelated policy PATCHes
   also validate all rules, so an existing violation will block them. A client
   update checks its own rules, allowing clients to be repaired individually.
4. Coordinate configuration writers, rerun the inventory with writes quiesced,
   then deploy every management and DCR writer. Mixed versions can reintroduce
   inconsistent rules. Recheck saved drafts before activation. Retain the report
   and the configuration versions it names as deployment evidence.

This procedure has not been run against an operator's production environment by
the repository tests. A successful fixture run does not establish production's
zero-violation precondition.

Correcting token-exchange policy changes its digest. Existing captured exchange
authority then requires fresh authorization. This is distinct from universally
revoking every authorization code, refresh token or session. Plan the correction
and affected users' reauthorization together.

## URI exchange and introspection boundaries

Cross-audience exchange requires the original authorization to produce an active
refresh lineage (`offline_access`, refresh issuance enabled and
`retainRefreshChain`). Without it the access token has no captured target grant,
regardless of whether the target is a URI or opaque identifier. Compare both
forms using the same client, scopes, rules and lineage conditions.

The client-credentials `resourceServers[].introspectionClients` binding covers
client-credentials tokens, including their same-audience exchange descendants.
It does not authorize introspection of unrelated authorization-code exchange
tokens. Those tokens retain their existing owner/audience visibility rule. A new
cross-grant resource-server binding would require a separate explicit contract
for registration identity, stored authority, currentness and revocation; simply
reusing client-credentials rules would create an implicit permission expansion.
