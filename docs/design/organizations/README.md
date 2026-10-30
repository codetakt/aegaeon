# Organizations Overview

Last updated: 2026-10-29

Status: active plan

Owner: Engineering

Audience: implementers, reviewers, integrators

Organizations is an optional service for application organizations, memberships,
roles, invitations, and bounded delegated administration within an Environment.
It is useful for business collaboration, education, associations, and other
applications in which one account participates in several organizations.

## Scope

The design is authorized for implementation. Authorization to implement is not a
claim that every interface below exists or has passed conformance testing.
Implementation and validation status are recorded separately. Existing product
assurance obligations and their acceptance state are unchanged.

## Canonical Documents

- `[design]` [Design and security contract](design.md)
- `[design]` [Permanent identity and physical authority integration](authority-integration.md)
- `[design]` [HTTP input and activation boundary](http-boundary.md)
- `[design]` [Explicit operator authority and currentness](operator-authority.md)
- `[design]` [Provisioning and bounded reconciliation](provisioning.md)
- `[design]` [Retained role vocabulary and versioned policy](role-policy.md)
- `[design]` [Delegated member API](member-api.md)
- `[design]` [Authorized audit history](audit-history.md)
- `[design]` [Durable audit outbox consumption](audit-delivery.md)
- `[design]` [Audit transition provenance](audit-transitions.md)
- `[design]` [Invitation capability and lifetime boundary](invitation-capabilities.md)
- `[design]` [Original approval and refresh lineage](original-authorization.md)
- `[design]` [Authenticated introspection recipients](introspection-recipients.md)
- `[design]` [Selected token enforcement](token-enforcement.md)
- `[model]` [Arithmetic proof boundary and remaining premises](arithmetic-verification.md)
- `[reference]` [Standards and extension boundaries](standards.md)
- `[workplan]` [Implementation status and integration dependencies](implementation-status.md)

## Reading Rule of Thumb

Start with the boundary model in the design. Use the standards document when
assessing interoperability or making a protocol support claim. An internal
membership model does not establish SCIM interoperability.

- [Own resource boundary](own-resource.md): dedicated DPoP context and currentness contract.

- [Consistent snapshots](snapshots.md): scoped transfer format, lifetime and import dependencies.
