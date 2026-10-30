# Aegaeon Organizations v1

Last updated: 2026-10-29

Status: active plan

Status note: user-adopted design and delivery principles; native candidate partial; product assurance not established

Owner: Engineering / Verification

Audience: implementers, protocol reviewers, integrators

## Authority and scope

This specification records the authorized generic Organizations feature and the
initial organization access profile. Its [versioned register](../../spec/organizations.v1.json)
provides stable requirements and exact source editions. It is subordinate to the
current four-role product-assurance authority; publication or implementation of
this document is not a verified-product declaration. The former server-assurance
contract present in some Git histories is not reinstated as claim authority.

The profile is an Aegaeon extension composed with OAuth/OIDC standards. It is
not a standardized OIDC Organizations feature, a SCIM implementation or an AuthZEN
adapter. Project requirements below are mandatory when enabled. The RFC clauses
retain their own actors, strength, triggers and exceptions. Project restrictions
such as one organization, no organization refresh token and online checks are
explicit choices, not universal requirements imposed by those RFCs.

## Adopted delivery principles

The user adopted the preceding design and standard/extension boundary on
2026-10-29. The following are mandatory delivery criteria, not optional future
hardening. They do not declare the current implementation verified.

- **ORG-POL01 — Standards conformance:** retain applicable RFC/OIDC duties and
  existing profile behavior; use explicit, versioned extension points. Standard
  conformance and Aegaeon-specific policy conformance are separate assessments.
- **ORG-POL02 — General product capability:** provide useful complete workflows
  for independent applications without customer-specific business dependencies.
  Vendor-specific API compatibility is secondary to a coherent generic product.
  Accepted identity preservation and migration contracts remain required.
- **ORG-POL03 — Secure defaults:** require explicit enablement, default-deny
  authority, least privilege, original ceilings, DPoP, bounded lifetimes, current
  state checks and explicit support grants. No implicit administrator bypass,
  permissive failure fallback or compatibility downgrade of these requirements.
- **ORG-POL04 — Formal verification:** prove scoped security/lifecycle properties
  and connect them to actual code, caller preconditions, storage, suppliers and
  artifacts under the existing assurance rules. An abstract model or finite
  test result alone does not establish the full product claim.
- **ORG-POL05 — Security tests:** test adversarial inputs, cross-scope access,
  escalation, replay, concurrency, failed stores and recovery; retain positive
  normal workflows, durable regressions and meaningful negative controls.

The versioned register maps these five cross-cutting policies to the existing
24 feature requirements and 15 composite proof work units. These policy IDs are
not additional atomic proof obligations. Competitive value is assessed through
usable, documented workflows and measured behavior, not an unsupported claim of
superiority to another vendor. Proof and security-test evidence must be assessed
separately and together before a verified release claim.

## Contract 1

### Responsibility and topology

Team → Tenant → Environment remains the operator/deployment hierarchy.
Environment owns issuer, user, client and key boundaries. An Organization is an
application access unit inside one Environment. One default authorization domain
is sufficient for normal setup; additional domains separate independent role and
target vocabularies inside the same issuer. Each target belongs to exactly one
domain. Business hierarchy, payment, enrollment and other business-object rules
remain application responsibilities. Attribute Mapping and LTI consume explicitly
authorized facts; neither creates membership or operator authority.

## Contract 2

### Identity and external identifiers

User identity is permanent `(iss, sub)` ownership backed by an internal user UUID
and retained ownership history. Selecting UUID subjects is a product profile,
not an OIDC requirement. Pairwise/public subject policy and imported subject
compatibility are explicit configuration; the initial UUID deployment profile
must not pretend every arbitrary issuer already uses UUID subjects.

Organization `identifier` is the opaque external ID supplied at creation. It is
not an encoded internal UUID. Lookup uses `(environment, target-derived domain,
external_id)` and yields the internal immutable ID. Every wire response preserves
the external value, including token response, JWT and introspection. Duplicate
creation under another actor is a conflict, not evidence of ownership. Exact
byte equality and tombstones survive deletion, migration and recovery.

## Contract 3

### Roles and state

Roles and privilege strings have a configured domain-specific meaning, never
an implicit global hierarchy. A role carries a version and explicit member-
management/assignable-role policy. Organization roles occur only in scoped
`authorization_details`. Configured platform `roles` may be disclosed to an
approved audience; no global role supplies business access by itself.

Organizations use provisioning → active → suspended, explicit restoration, and
terminal deletion. Memberships use invited → active → suspended/removed.
Invitations cannot restore removed/suspended membership. A separately authorized
rejoin creates a new incarnation. Promotion/reactivation/role expansion needs
new authorization; demotion invalidates issued selected-organization tokens and
permits a new exchange only within the old ceiling. Other organizations retain
their independent grants, except for genuinely global identity/client/root events.

The first administrator accepts a provisioning invitation before atomic
activation. Normal member mutations cannot remove the last effective admin.
Security suspension of a global identity always remains possible; an organization
without an effective admin refuses delegated changes and requires audited
operator recovery. Recovery is not an implicit grant of business access.

## Contract 4

### Authorization and token exchange

The authorization server captures membership/role generations, approved targets,
client registration, identity and DPoP key with the original grant. Capture must
occur after user authorization of the relevant capability and before root
publication. Existing login grants with no organization ceiling require a new
authorization; enabling Organizations must not upgrade them silently.

The initial profile uses an authenticated confidential OAuth client and RFC 8693
POST token exchange. `subject_token_type` is the OAuth access-token identifier;
`requested_token_type`, if present, selects an access token. Exactly one
registered `audience` and one RAR detail are accepted. This profile rejects
`resource`, actor-token parameters, repeated parameters, organization-token
chaining and service-token subjects. Other existing exchange profiles retain
their separate contracts. Scope and privileges can only narrow approved rights.

`privileges` omitted requests the nonempty permitted intersection; present means
a nonempty, unique, known subset. `null`, empty, unknown fields/types and duplicate
JSON members are rejected. An optional `admin_access_grant_id` selects an already
authorized administrative grant; the client cannot choose `access_basis`.

```json
[{"type":"https://github.com/codetakt/aegaeon/spec/organization-access/v1",
  "identifier":"school:west-campus", "privileges":["members.read"]}]
```

The [wire schema](../../spec/organization-access.schema.json) defines request and
response shapes. The output contains the same external identifier, nonempty
privileges and `access_basis` (`membership` or `administrative_grant`). Only the
latter includes its bound administrative grant ID. These fields live under the
project-controlled RAR type and are not new unqualified top-level JWT claims.

The JWT includes RFC 9068 `iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `client_id`,
`typ=at+jwt`, a permitted signature and `cnf.jkt`. RFC 9068 includes RS256 support;
a working EdDSA-only fixture does not establish that profile's conformance.
Output `aud` is one registered target. The response includes
`issued_token_type=urn:ietf:params:oauth:token-type:access_token`,
`token_type=DPoP`, granted `scope`, `expires_in` and matching authorization details.
No organization refresh token is issued. Expiry is the minimum of 300 seconds,
parent expiry, root/grant horizon and any administrative grant expiry. Original
`auth_time`, `acr` and `amr`, when used, never refresh by exchange or refresh.

Malformed or unacceptable source token uses RFC 8693 `invalid_request`;
unavailable target authority uses `invalid_target`; structured detail failure or
attempted privilege expansion uses `invalid_authorization_details`; scope
expansion uses `invalid_scope`. Client authentication and DPoP retain their
protocol errors. Authority-store unavailability is an explicit service failure.
Errors must not reveal membership existence to an unauthorized caller.

## Contract 5

### Online status and races

Aegaeon's own resource endpoints enforce token/DPoP validation and current
organization authority. External resource servers must do the corresponding
validation and obtain fresh authenticated, target-scoped introspection for each
operation. Introspection returns the token's `cnf.jkt`; it does not validate the
client's resource-request DPoP proof. The resource server checks proof signature,
key, `ath`, method, URI, nonce/time and replay itself. This separation follows
RFC 9449 section 6.2.

No positive introspection cache or offline fallback is allowed in this profile.
A token cache may retain a token but cannot skip a new authorization decision.
A check begun after a successful suspension response must reject the affected
old authority. Previously admitted business I/O may finish; this is not an
atomic transaction over external business data or retroactive I/O cancellation.

Use authoritative primary storage and a consistent snapshot. Root publication
and revocation guards remain necessary across PostgreSQL and token/root storage.
After publication, issuance rechecks authority before delivery. A concurrent
suspension may produce a token already inactive at receipt; it cannot permit a
later online decision to accept revoked authority. No distributed atomic commit
is assumed. Store failures refuse access. Login/exchange do not read an external
business database; that independence does not promise availability if Aegaeon's
own required services are unavailable.

## Contract 6

### Management, queries and support access

Delegated mutation uses the acting user, a dedicated management audience/scopes,
DPoP, original ceiling and current permission. It checks both added and removed
roles. General operator authority and read-only reconciliation credentials are
separate. Listing, member reads and pagination bind the same scope; unauthorized
reads do not become existence probes. Export requires separate authority.

Domain provisioning and first-admin invitation need explicit domain authority,
not a preexisting membership. Temporary business support access needs an explicit
AdminAccessGrant with reason, one organization/target/privilege set, user/client/
root/key bindings and expiry ≤300 seconds. Require original MFA within 300
seconds; merely seeing the literal `mfa` or a platform role is insufficient.
Accepted authentication policy and evidence establish freshness and strength.

## Contract 7

### Invitations and identity lifecycle

Invitation issuance binds intended recipient, organization, role ceiling,
inviter authority and expiry. Default lifetime is 24 hours. Store only a hash of
a 256-bit random capability. GET may display a confirmation page but never accept;
POST requires an authenticated principal and fresh recipient-address control.
Acceptance rechecks inviter/current assignable roles and organization state in
one transaction. Concurrent acceptance has one effect; suspended/removed users
or memberships cannot be revived. No automatic email-based account linking.

Aegaeon owns link issuance, revocation and acceptance. Delivery may use a
configured transport with scoped templates and a protected outbox, without
membership authority. Mail delivery alone is not acceptance. Self-registration
and recovery follow explicit Environment policy and selected subject format;
unregistered invitees complete these flows before acceptance.

## Contract 8

### Transaction, replay and audit

Each mutation commits state, audit, outbox and receipt together. The HTTP
integration owns the transaction and rolls back on any error. Lost responses,
commit uncertainty and retries must have a bounded recovery procedure.

Mutations of existing representations require a strong ETag precondition;
`If-Match` comparison follows RFC 9110 section 13.1.1. A stale comparison returns
412 with no effect. The API requires a specific version (wildcard is insufficient
for its concurrency policy). Idempotency keys bind actor, internal client
registration, domain, operation and semantic payload including reason. Replay
rechecks current authority before returning a prior result. Same key with a
changed payload returns conflict; equal external IDs alone do not deduplicate.

Audit includes authority basis and before/after version identifiers. Credential,
invitation and excess personal data must not leak through logs/errors. Define
retention/export rights. Outbox delivery is at least once with deduplication;
revocation depends on authoritative state, not delivery completion.

## Contract 9

### Export, import, migration and restore

Export a versioned, consistent, complete authorized snapshot with counts and
checksums covering identities/subject history, organization IDs, memberships,
roles, invitations/status and relevant audit. No usable invitation secret or
password hash appears in an ordinary organization export. Credential transfer is
a separate protected operation with explicit compatibility checks; unsupported
password formats require reset rather than pretending migration succeeded.

Migration validates ownership and rejected rows, compares shadow decisions,
freezes membership writes for final delta and switches one authority epoch.
Legacy/new parsers may coexist only under an explicit per-scope authoritative
selection; never union their privileges or use the old source on failure.
Invalidate old roots and reauthorize at cutover. Business provisioning uses
inactive preparation, authority activation and bounded reconciliation; an
interrupted saga cannot authorize business access prematurely. Retire old
application-specific adapters only after the migration acceptance evidence.

Restore and rollback invalidate prior roots, reconcile single-writer changes,
and establish an authority epoch that cannot roll back with the restored data.
Permanent subject and external-ID ownership history must be reconciled before
activation. Mechanism selection and actual recovery proof are required work;
monotonic integers in the restored database are insufficient.

## Contract 10

### Limits, configuration and compatibility

Initial bounded profile: 256 organizations per captured grant, 32 targets,
64 role definitions per domain, 256 selected privileges, 128 ASCII bytes per
role/privilege key (`[A-Za-z0-9._:-]`), 256 UTF-8 bytes per external ID and
65,536 bytes of decoded organization authorization details. Duplicate JSON
members are rejected before deserialization. HTTP body/form overhead, pagination,
transaction deadlines, invitation rate/storage retention and audit capacity must
be assigned finite enforced budgets before their interface is enabled; no
unbounded or silently truncated fallback is permitted. These are supported
profile bounds, not proof that maximum-load normal operation already succeeds.

Counters never wrap; an exhausted generation retains a terminal revocation
operation. Configuration changes preserve current authority ceilings. Disabled
features reject their input and do not advertise the RAR type. SCIM Groups and
enterprise `organization` describe provisioning data, not this authorization
contract. No SCIM/AuthZEN adapter, hierarchical grants, offline validation or
native-login selection is included in v1. Optional future profiles require a
versioned decision and their own applicability/evidence inventory.

## Contract 11

### Implementation and assurance acceptance

A feature requirement has independent specification, implementation, test and
proof states. The internal candidate at `535c31a351e8984225542ff822cdc2a1ef5dd31a`
is incomplete. Its external-ID exchange mismatch is a known defect: the native
wire parser/serializer currently assumes `organization_<internal UUID>`.
The API and lifecycle integrations remain open. Seventeen focused tests and
552 standard tests (seven overlapping) are finite prior observations, not
proof of this full contract or a released feature.

The Organization extension is evaluated within the existing four authority
roles. Preserve all applicable legacy requirements and add explicit new
obligations; old 8,805 IDs are not a complete census of new functionality.
A proof must connect the actual parser/authentication/storage/caller boundaries
to its preconditions, cover full allowed histories/concurrency/failure domains,
and connect the result to real providers, configuration and release artifacts.
Normal functionality, resource/security checks and final review remain required.
External resource-server enforcement is a deployment contract, not an Aegaeon
server theorem. Required own connection code remains in scope; whole-SDK
assurance is not silently added.

## Requirement register

The following stable IDs are the implementation and regression review units.
Their exact statements, standards clauses and proof/gap relations are recorded
in the versioned register. Splits or changes retain old-to-new correspondence.

| ID | Required capability | Contract |
| --- | --- | --- |
| ORG-R01 | Scope and ownership | [contract-1](#contract-1) |
| ORG-R02 | Permanent subject ownership | [contract-2](#contract-2) |
| ORG-R03 | External organization identifiers | [contract-2](#contract-2) |
| ORG-R04 | Role authority and platform roles | [contract-3](#contract-3) |
| ORG-R05 | Lifecycle and security suspension | [contract-3](#contract-3) |
| ORG-R06 | Original authorization ceiling | [contract-4](#contract-4) |
| ORG-R07 | Exchange admission | [contract-4](#contract-4) |
| ORG-R08 | Wire consistency | [contract-4](#contract-4) |
| ORG-R09 | Sender and authentication binding | [contract-4](#contract-4) |
| ORG-R10 | Online revocation | [contract-5](#contract-5) |
| ORG-R11 | Delegated management | [contract-6](#contract-6) |
| ORG-R12 | Explicit administrative access | [contract-6](#contract-6) |
| ORG-R13 | Invitations | [contract-7](#contract-7) |
| ORG-R14 | Signup and recovery | [contract-7](#contract-7) |
| ORG-R15 | Transactional mutations and replay | [contract-8](#contract-8) |
| ORG-R16 | Audit and disclosure | [contract-8](#contract-8) |
| ORG-R17 | Complete authorized export | [contract-9](#contract-9) |
| ORG-R18 | Migration and retirement | [contract-9](#contract-9) |
| ORG-R19 | Restore and rollback | [contract-9](#contract-9) |
| ORG-R20 | Scoped queries | [contract-6](#contract-6) |
| ORG-R21 | Numeric and resource bounds | [contract-10](#contract-10) |
| ORG-R22 | Configuration and advertisement | [contract-10](#contract-10) |
| ORG-R23 | Consumer obligations and availability | [contract-5](#contract-5) |
| ORG-R24 | Release and verified claim | [contract-11](#contract-11) |

## Standards interpretation

The pinned RFC 8693 request/response and RFC 9396 sections 2, 5–10 supply the
exchange and structured-authority mechanisms. RFC 9068 supplies the JWT profile
and claim vocabulary; RFC 9449 supplies sender binding. RFC 7662 status checks
and RFC 7009 revocation do not themselves define membership versions or this
profile's stronger revocation boundary. OIDC Core errata set 2 section 5.7
supplies issuer-local subject stability, not a UUID requirement. RFC 9110 supplies
conditional-request semantics, not the project's idempotency namespace.

Source acquisition and selected raw-byte anchors are versioned in the register.
Existing protocol dependencies remain applicable. Full transitive requirement
and errata closure belongs to the affected conformance/proof work, and remains
open where not established; no source is marked completely read from a section
lookup. SCIM RFC 7643/7644 are comparison sources; implementing the native
membership contract does not claim their provisioning endpoints.
