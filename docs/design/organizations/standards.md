# Organizations Standards and Extension Boundaries

Last updated: 2026-10-29

Status: active plan

Owner: Engineering

Audience: protocol implementers, reviewers, integrators

## Classification

Organizations is an Aegaeon product capability built on existing identity and
authorization standards. Its organization access profile defines the additional
semantics needed to compose those standards. It is not a standardized OIDC
Organizations protocol. This assessment concerns the sources below; it is not
a claim that no related specification exists elsewhere.

| Concern | Existing specification | Additional Aegaeon contract |
| --- | --- | --- |
| User authentication and identity | [OIDC Core 1.0 section 5.7](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability), including issuer-local stable `sub` | Environment ownership, lifetime identity history, organization selection |
| User/group provisioning | SCIM 2.0, RFC 7643 and RFC 7644 | Mapping to Organizations, organization-local roles, authoritative writer, deletion/reactivation rules |
| Token exchange | RFC 8693 | Allowed clients, targets, original grant ceiling, organization selection, root lineage |
| Structured authorization data | RFC 9396 | Organization access type, field semantics and narrowing rules |
| JWT access tokens | RFC 9068 | Organization-scoped privilege vocabulary and access basis |
| Sender constraint | RFC 9449 | DPoP required in the initial organization access profile |
| Online token status | RFC 7662 | Membership/version checks, no positive cache, rejection boundary after suspension |
| External authorization decisions | OpenID AuthZEN Authorization API 1.0 | Optional future decision adapter and consistency policy |

The table identifies building blocks, not implemented or certified support for
every listed interface. The initial implementation owns membership state
natively; SCIM and AuthZEN adapters require separate implementation and tests.

## SCIM is a provisioning boundary

[RFC 7643 section 4.2](https://www.rfc-editor.org/rfc/rfc7643.html#section-4.2)
defines Group membership but explicitly leaves authorization consequences to
the service provider. Section 4.1.2 defines roles and entitlements without a
shared privilege vocabulary. Section 4.3's enterprise `organization` attribute
is an organization name, not a multi-organization membership/role relation.

[RFC 7644 section 2](https://www.rfc-editor.org/rfc/rfc7644.html#section-2)
requires requests to be authorized but does not specify that authorization
model. Section 6 discusses multi-tenancy without imposing Aegaeon's Team,
Tenant, Environment, or AuthorizationDomain hierarchy.

A future SCIM adapter can provision users and suitable groups. It must define
how direct membership, supported roles and lifecycle operations map to this
service. Organization-local roles and invitation acceptance must not be inferred
from a free-form enterprise organization name or an untrusted profile attribute.
SCIM group synchronization does not itself authorize the SCIM client to assign
every role. Schema extensions, resource types and discovery must be specified
and tested before claiming an Organizations SCIM profile.

## OAuth supplies the exchange, not the organization policy

[RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) supplies the token exchange
grant. It does not turn an arbitrary user token into permission to select any
organization, mandate membership administration, or automatically propagate
every membership change to exchanged tokens. Business delegation and OAuth's
actor-token delegation are distinct; the initial profile accepts no actor token.

[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) supplies
`authorization_details`. Its `type` selects application-specific semantics.
The organization type, privilege keys, membership selection and administrative
access basis in this design are Aegaeon extensions. Supporting the JSON
parameter alone does not support this type or preserve its authority.

The [original approval contract](original-authorization.md) distinguishes the
`organization-grant/v1` parent permission from the `organization-access/v1`
selected credential. Its explicit approval, limits and snapshot semantics are
Aegaeon rules, not RFC 9396 requirements. Both remain unadvertised until the
corresponding runtime paths and resource checks are ready.

[RFC 9068 section 2.2.3.1](https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2.3.1)
provides authorization claim names such as `roles`, `groups` and `entitlements`.
It does not assign shared meanings to role values or define their organization
scope. This design keeps organization privileges together in one authorization
detail instead of emitting ambiguous unscoped duplicates.

[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html) provides authenticated
introspection. Requiring each protected operation to obtain a fresh decision,
and including organization and membership versions in that decision, is the
Aegaeon profile's revocation contract. Token expiry and DPoP alone do not provide
that contract. [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) supplies the
proof-of-possession mechanism, including resource-side proof validation.

## AuthZEN and draft work

[OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
is a final specification for decision and search communication between policy
decision and enforcement points. It does not define this service's organization
database, invitation workflow, delegation ceiling or transactional revocation.
An adapter is a possible extension; native membership storage does not need to
implement a separate policy decision service first.

The [AuthZEN authorization claims profile, Draft 1 dated 2026-10-13](https://openid.github.io/authzen/authzen-oauth-authorization-claims-1_0.html)
is related work on obtaining JWT authorization claims through resource search.
It explicitly separates enrichment from the authority to issue a token. It is
draft work, not a final standard adopted by this design. Changes to a moving
draft must be reviewed before a future adapter adopts them.

## Naming and conformance

Use the product name **Aegaeon Organizations** and describe the wire behavior as
the **Aegaeon organization access profile**. Publish the extension schema,
version, errors, trust boundaries and test cases. Do not advertise a standard
organization claim or IETF-registered authorization detail type.

The initial type identifier is the project-controlled URI
`https://github.com/codetakt/aegaeon/spec/organization-access/v1`. It identifies
semantics and need not be dereferenced by the server. The
[IANA URN namespace registry](https://www.iana.org/assignments/urn-namespaces)
does not register an `aegaeon` namespace as of this review; an invented URN must
not be presented as a registered standard identifier. Future incompatible changes require a new type
and explicit migration; callers cannot negotiate away authority checks.
