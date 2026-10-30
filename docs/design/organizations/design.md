# Organizations Design and Security Contract

Last updated: 2026-10-29

Status: active plan

Owner: Engineering

Audience: implementers, security reviewers, integrators

## Purpose and generic use cases

One account can join several business organizations, schools, associations or
project sponsors with different roles in each. An organization administrator
can invite and manage its members without obtaining control of their global
identity or other organizations. A resource server obtains authority for one
selected organization and one audience. An explicitly authorized support
operator can obtain temporary access with a recorded reason.

These are optional capabilities. A consumer application or a deployment with
no shared membership model need not enable Organizations. Course enrollment,
grades, documents, contracts and other business objects remain the resource
server's responsibility. LTI contexts, deployments and role vocabularies are
not automatically organization identifiers or role grants.

## Boundary model

Team owns the service and operator administration. Tenant groups deployments
and naming/region configuration. Environment remains the issuer, identity,
client and key boundary. An application Organization lives inside one
Environment; it does not replace Team or Tenant. Sharing membership does not
require cloning clients or configurations for each Organization.

An AuthorizationDomain groups Organizations, role definitions and audiences
that share a privilege vocabulary. Enabling the feature creates one default
domain internally. Additional domains are optional for independent authority
models using the same issuer. Each target audience belongs to exactly one
domain; the registered target determines the domain. Caller-supplied domain
names cannot expand access. Different issuers, identities or keys require
separate Environments.

End-user principals and service operators remain separate. Organization roles
never create Team memberships or management-plane sessions. Existing legitimate
operator powers remain explicit and audited. Attribute Mapping may transform
and disclose approved claims but cannot manufacture membership authority.

## State and identity ownership

The native PostgreSQL store is the initial membership authority. Entities are:
AuthorizationDomain, Organization, Membership, RoleDefinition, RoleAssignment,
DelegationPolicy, Invitation, AdminAccessGrant, AuthorizationSnapshot and an
atomic audit/outbox record. External directory adapters are future interfaces
with one selected writer per authority scope, not an implicit second master.

Internal references use UUIDs and Environment/domain foreign keys. External
organization IDs are opaque 1–256 UTF-8 bytes without control characters. They
are compared exactly, without case folding or Unicode normalization, and stay
reserved after deletion. Display names are not identity. Reusing an external
ID is neither proof of ownership nor an idempotency mechanism.

Membership binds the internal end-user UUID and its identity history, not just
an email address or a currently reusable textual subject. OIDC `(iss, sub)`
ownership must be durable through rename and deletion. Existing accounts are
not silently renamed or linked by email. Production activation depends on the
subject ownership foundation; UUID membership keys alone do not repair token
subject reassignment elsewhere in the issuer.

Organizations transition provisioning → active → suspended, with explicit
restoration and terminal deletion. Memberships transition invited → active →
suspended/removed. Invitation acceptance must not restore a suspended or
removed membership. Rejoining is a separate authorized operation and creates a
new incarnation. Deleted organization IDs remain tombstones.

## Authority and mutation invariants

Every operation checks Environment, domain, active identities and current
authority. The effective authority is the intersection of the original grant,
current membership, original/current client permission, target permission and
requested restriction. Missing, malformed or unavailable state never permits
access. An added role or new membership does not extend an existing grant.

Each organization and membership has an authorization revision and a grant
generation. Demotion increments the revision and invalidates old access tokens;
a fresh exchange can narrow the original grant. Promotion, reactivation or
rejoining increments the grant generation and requires new authorization.
Restoring an organization increments its generation. Expanding a role's meaning
requires a new role version and authorization. Unrelated organizations retain
their own authority. Counters cannot wrap or be reset to revive old grants.

Changes use transactionally checked revisions (`If-Match` at HTTP boundaries).
An idempotency key is scoped to actor, client, domain and operation, bound to
the complete semantic request digest. A mismatched replay fails with conflict.
Client bindings and receipt scopes include the internal registration UUID;
reusing a public `client_id` cannot acquire an earlier registration's authority
or successful mutation receipt.
Creation retains an ownership receipt beyond any short-lived response cache.
Mutations, audit and outbox entries commit together. Outbox delivery may be
repeated and consumers deduplicate; it is not the revocation authority.

Organization row locks serialize membership mutations and last-administrator
checks. Two concurrent removals cannot both observe another administrator and
leave an active organization without one. An administrative role is explicit
policy, not inferred from a role's name. Counter exhaustion reserves a terminal
revocation path; it never permits a grant extension.

## Delegated management and invitations

Delegated requests use a dedicated domain-specific management audience, required
scopes, current authority, original grant ceiling and DPoP. A business API token
is not a management credential. Delegation policy defines allowed actions,
targets, assignable roles and authentication conditions. An organization admin
can manage only its own organization and explicitly assignable roles, without
global account deletion, domain administration or operator privileges.

Invitations expire after 24 hours by default and contain 256-bit random secrets
stored only as hashes. A one-use POST accepts an invitation; a GET or email
scanner cannot consume it. Acceptance requires an authenticated user with
current control of the intended address. It rechecks inviter delegation,
organization state and assignable roles in the mutation transaction. Invitation
possession does not link accounts. Public signup remains a separate policy.
Delivery uses the outbox; delivery failure cannot grant membership.

## Explicit administrative access

Domain-wide administration is separate from ordinary membership. An explicit
AdminAccessGrant selects organization, audience, roles and reason for at most
five minutes. It binds user, client, original grant/root and DPoP key, and
requires fresh MFA within five minutes based on the original authentication
context. Refresh and exchange cannot reset `auth_time`, `acr` or `amr`.

The original authorization must already permit this bounded activation.
Subsequent promotion to administrator requires reauthorization. No global role
implicitly creates membership. Output identifies `access_basis` as
`administrative_grant`, while ordinary member access uses `membership`.

## Organization access profile

The first profile uses a confidential OAuth client, Token Exchange and online
resource checks. A browser-facing backend is one deployment of that profile,
not a requirement of the general Organizations data model. Native login
selection and offline resource validation need separate profiles and tests.

The client selects a registered audience and exactly one authorization detail:

```json
{
  "type": "https://github.com/codetakt/aegaeon/spec/organization-access/v1",
  "identifier": "school-01",
  "privileges": ["documents.read"]
}
```

`identifier` is the exact stored external ID in the authenticated Environment
and registered target's domain. It is not an encoding of the internal UUID.
Case, Unicode normalization differences and leading/trailing spaces remain
distinct. A prefix-looking external value is treated as opaque data.

`privileges` may be omitted to request the permitted intersection; if present,
it must be nonempty, unique and known, and may only narrow that intersection.
The caller cannot choose `access_basis`. An administrative request additionally
selects its bound `admin_access_grant_id`. The response, JWT and introspection
carry the same nonempty granted privileges and server-selected access basis.
Organization privileges are not duplicated in an unscoped `roles` claim.

Output is one audience, one organization, a DPoP-bound JWT access token and no
organization refresh token. Lifetime is at most 300 seconds and no longer than
the parent token, root/grant horizon or administrative grant. The original
authorization snapshots membership ceilings and versions server-side. Existing
cross-audience refresh-root requirements continue to apply. No actor token,
unknown detail type, organization-token chaining or implicit organization switch
is accepted. Selection changes start from the parent authorization.

Errors retain the established token exchange contract: `invalid_target` for
unavailable target authority, `invalid_authorization_details` for invalid
structured selection, `invalid_scope` for scope expansion, and existing source
token errors. State unavailability is a service error, never an empty success.
See [standards boundaries](standards.md) for standard versus profile semantics.

## Online revocation and issuance races

Each resource operation validates issuer, audience, JWT and DPoP including
`ath`, `htm`, `htu` and replay protection, and obtains authenticated,
target-scoped introspection. Positive introspection results are not cached in
this profile. The check validates the root lineage plus authoritative primary
PostgreSQL organization, membership, role and administrative grant versions.

After a suspension response succeeds, an authorization check begun afterward
must reject the revoked authority. An operation already admitted can finish;
this does not cancel past I/O or provide a transaction over resource-server
business writes. SDK verification must make the complete check one entrypoint.

PostgreSQL provides a consistent authority snapshot. Existing Redis root and
publication guards remain necessary. Issuance snapshots PostgreSQL, registers
the token under its root guard, then rechecks authority before delivery. A race
can yield a token already inactive on receipt, but cannot let a later online
check accept revoked authority. No distributed atomic commit is assumed.

Authority or token-store unavailability refuses protected operations. There is
no silent offline fallback. Backup restoration invalidates pre-restore tokens
and requires reauthorization plus ownership-history reconciliation; a restored
integer counter alone is not rollback protection.

Client caches must distinguish issuer, client, session root, audience,
organization, scopes, privileges, DPoP key and administrative grant. A shared
client backend compromise may affect every session it holds.

## Integration, migration and export

Business provisioning can prepare an inactive record, create a provisioning
Organization, accept the first administrator invitation and activate the
Organization atomically, then activate the business record after its own
readiness checks. Suspension stops business access first and requests authority
suspension; a failed request remains pending. Read-only reconciliation does not
receive general authority to repair membership by itself.

Migration inventories identities, membership, roles and credential compatibility;
deploys inactive compatible readers; compares shadow decisions; briefly freezes
membership writes; applies the final delta; switches the single authority;
and invalidates old domain grants for reauthorization. Do not union old and new
claims or accept either authority on failure. Rollback resynchronizes changes
and invalidates both sets of roots. Unsupported password formats require reset.
Invited accounts do not become active members merely by import.

Export includes identity correspondence, stable organization IDs, memberships,
roles, states, history and authorized audit records. Credential secrets require
a separate protected mechanism and never enter an ordinary organization dump.

## Delivery and acceptance

Deliver reviewable units: native domain/state foundation; delegated management
and invitations; grant capture/exchange/online checks; bounded administrative
access; migration/export and client integration. Preserve compatibility of
existing application-specific grants until an explicit migration retires them.

Required regressions include cross-Environment/domain access, subject reuse,
last-admin races, stale writes, idempotent replay conflicts, invite replay and
inviter revocation, demotion/promotion/rejoin/restore, administrative grant
binding, token scope/audience/DPoP substitution, parent revocation, authority
outages, concurrent mint versus suspension, and migration/rollback history.
Source tests, executed database/API tests, standard conformance, formal proof,
review acceptance and release activation are separate completion states.
