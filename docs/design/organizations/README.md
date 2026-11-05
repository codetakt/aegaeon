# Organizations Overview

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: implementers, reviewers, integrators, operators

Organizations is an optional service for application organizations, memberships,
roles, invitations, and bounded delegated administration within an Environment.
It is useful for business collaboration, education, associations, and other
applications in which one account participates in several organizations.

## Scope

The design is authorized for implementation. Authorization to implement is not a
claim that every interface below exists or has passed conformance testing.
Implementation and validation status are recorded separately. Existing product
assurance obligations and their acceptance state are unchanged.

## Recovery responsibility revision

Use the [adopted storage and recovery rules](recovery-responsibilities.md),
[security and verification assessment](recovery-security.md), and
[implementation workplan](recovery-workplan.md) for the current design. DB
operators select WAL/PITR policy and the restore point. The application owns
domain consistency, audit, safe volatile-state loss and post-restore convergence.
The operator path below uses the selected database and version 2 runtime
configuration. Predecessor control-store documents are historical references.

## Operator path

Start with [implementation status](implementation-status.md) for the current
candidate and its remaining CI, review, supplier and assurance conditions. The
following contracts explain the usable path; passing a component check or
changing a flag does not qualify a production deployment or discharge a proof.

1. **Prepare the mandatory runtime boundary.** Follow the
   [single migration](migration-composition.md), [generation contract](runtime-generation.md)
   and [restore runbook](restore-runbook.md). Use `aegaeon-organizations-server`
   with the protected absolute-file input `AEGAEON_ORGANIZATION_RUNTIME_CONFIG`.
   A disabled policy does not remove this boundary. Verified PostgreSQL TLS,
   selected generation, explicit Environment inventory and exclusion of old
   writers are required. No Redis or separate control DB is required.
2. **Configure management authority and the domain.** With a current interactive
   management session and Origin/CSRF protection, [initialize the disabled default
   domain and explicit grants](http-boundary.md#initial-management-configuration-endpoints).
   `configure`, `provision` and `reconcile` are separate capabilities; Team
   ownership does not grant membership. [Register targets and active client
   bindings](operator-authority.md#target-registration-and-configuration-reads)
   for the current confidential DPoP-required client. Native APIs use
   `{issuer}/organizations` and `{issuer}/organization-invitations`, both registered
   as management targets, with explicit client privileges and OAuth target/scope
   policy.
3. **Enable the supported profile explicitly.** The database-backed Environment
   policy uses the keys below; removed startup-environment fallbacks do not
   replace them. The [browser configuration contract](browser-authorization.md#explicit-configuration-candidate)
   explains their joint validation. Retain an active RS256 JWT signing key and
   complete normal configuration activation/restart before using the new policy.

   | Environment policy key | Required value |
   | --- | --- |
   | `policy.authorizationDetailsTypesSupported` | Exactly `https://github.com/codetakt/aegaeon/spec/organization-grant/v1` and `https://github.com/codetakt/aegaeon/spec/organization-access/v1`; empty is the disabled default |
   | `policy.allowedGrantTypes` | Includes `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:token-exchange` |
   | `policy.jwtAccessTokensEnabled` | `true` |
   | `policy.retainRefreshChain` | `true` |
   | `policy.enforceRefreshSenderBinding` | `true` |

   Configure the [HTTPS delivery adapter](invitation-delivery.md), then use the
   separate [domain enable operation](operator-authority.md#explicit-domain-lifecycle).
   These settings do not create membership or authorize an original grant.
4. **Create the organization and first invitation.** [Provision](provisioning.md)
   with the exact `externalId`, a reason and `Idempotency-Key`; retain the returned
   plain UUID and strong ETag. The organization remains provisioning with no
   membership. [Issue its first-administrator invitation](invitation-flow.md#operator-http-interface)
   using that ETag, an explicit recipient and roles containing a member manager.
   The [delivery worker](invitation-delivery.md#durable-attempts-and-recovery) processes
   one named item with its private transport credential; the management response
   never exposes the invitation capability.
5. **Authenticate the recipient and accept.** If needed, configure and complete
   [invitation-linked registration](identity-enrollment.md); this creates neither
   a session nor membership. After ordinary login, obtain the separate
   [DPoP recipient credential](invitation-flow.md#recipient-http-credential-profile)
   for `{issuer}/organization-invitations` and `organization.invitation.accept`.
   Request the fresh delivered address challenge, then POST both capabilities to
   accept. Link navigation never accepts. First acceptance creates membership and
   activates the provisioning organization; it does not expand an existing grant.
6. **Obtain fresh organization authority.** Start [new original consent](original-authorization.md)
   with PKCE S256, `prompt=consent`, `offline_access` and `dpop_jkt`. Redeem the code
   as the confidential client, then [exchange its parent authorization](token-enforcement.md)
   for one registered audience and one exact external organization identifier.
   The selected token is DPoP-bound, lasts at most 300 seconds and has no selected
   refresh token.
7. **Use the resource with a fresh proof.** Call [`GET /organizations/context`](own-resource.md)
   with the selected `organization.context.read` privilege, `Authorization: DPoP`
   and a fresh method/URI/`ath`-bound proof. Its UUID and version tag support the
   separate [member](member-api.md) and [delegated invitation](delegated-invitations.md)
   operations, each with its own current authorization. An external resource
   server must authenticate for [online introspection](introspection-recipients.md)
   and independently verify presentation DPoP; offline JWT validation is insufficient.

Keep credentials and delivered capabilities out of URLs and logs. Mutation
retries retain the original idempotency key and payload and recheck authorization.
Disabling the domain or changing authority invalidates old credentials; recovery
continues to require the explicit serving/recovery contract.

## Canonical Documents

- `[design]` [Storage and recovery responsibilities](recovery-responsibilities.md)
- `[model]` [Recovery security and verification assessment](recovery-security.md)
- `[workplan]` [Recovery implementation workplan](recovery-workplan.md)
- `[policy]` [Restored credential policy](restore-credential-decision.md)
- `[design]` [Durable authentication budgets](durable-security-budgets.md)
- `[design]` [Durable replay decisions](durable-replay-decisions.md)
- `[design]` [Backend migration plan](recovery-storage-migration.md)

- `[design]` [Design and security contract](design.md)
- `[design]` [Permanent identity and physical authority integration](authority-integration.md)
- `[design]` [HTTP input and activation boundary](http-boundary.md)
- `[design]` [Explicit operator authority and currentness](operator-authority.md)
- `[design]` [Current-state restoration comparison](restore-current-state.md)
- `[design]` [Drained store restart continuity](store-continuity.md)
- `[design]` [Proposed interrupted-operation recovery and AWS storage redesign](recovery-redesign.md)
- `[design]` [Proposed recovery writer and shared-state inventory](recovery-redesign-inventory.md)
- `[design]` [Proposed recovery acceptance contract and design review](recovery-redesign-acceptance.md)
- `[design]` [Proposed recovery performance and capacity design](recovery-performance.md)
- `[plan]` [Proposed 10,000 HTTP/s recovery qualification](recovery-performance-qualification.md)
- `[design]` [Credential replacement before cutover](cutover-credentials.md)
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

### AWS redesign sources

The [recovery proposal](recovery-redesign.md) uses these official sources,
reviewed on 2026-11-04. Provider documentation does not qualify the implementation.

| Source | Contract considered by the proposal |
| --- | --- |
| [RDS Multi-AZ DB instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZSingleStandby.html) | Synchronous standby replication |
| [RDS privileges](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Appendix.PostgreSQL.CommonDBATasks.Roles.rds_superuser.html) | Managed privileges and administrator limitations |
| [RDS failover](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.Failover.html) | Writer replacement and connection recovery |
| [IAM database authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html) | Connection authentication versus existing-session lifetime |
| [MemoryDB consistency](https://docs.aws.amazon.com/memorydb/latest/devguide/consistency.html) | Primary durability and replica read semantics |
| [ElastiCache durability options](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Durability.Options.html) | Synchronous/asynchronous acknowledgement and eviction |
| [ElastiCache durability limitations](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/Durability.Limitations.html) | Engine, cluster, replica and deployment prerequisites |
| [PostgreSQL 18 transaction isolation](https://www.postgresql.org/docs/18/transaction-iso.html) | Serialization monitoring, whole-transaction retry and snapshot limits |
| [PostgreSQL 18 table partitioning](https://www.postgresql.org/docs/18/ddl-partitioning.html) | Partition retirement and uniqueness/partition-key restrictions |
| [PostgreSQL 18 explicit locking](https://www.postgresql.org/docs/18/explicit-locking.html) | Transaction-scoped advisory lock lifetime and shared/exclusive modes |

### Product design navigation

Start with the boundary model in the design. Use the standards document when
assessing interoperability or making a protocol support claim. An internal
membership model does not establish SCIM interoperability.

- [Own resource boundary](own-resource.md): dedicated DPoP context and currentness contract.

- [Consistent snapshots](snapshots.md): scoped transfer format, lifetime and import dependencies.

- [Durable form capabilities and DPoP challenges](durable-form-challenges.md)
- [Durable upstream continuations](durable-upstream-continuations.md)
- [Durable step-up challenges](durable-stepup.md): current SQL state, asynchronous completion and bounded cleanup.

- [Durable management sessions](durable-management-sessions.md): SQL authority, capacity and transaction-bound final checks.

- [Atomic authorization and grant migration](durable-grant-migration.md): coupled SQL transaction boundaries and implementation ToDo.

Browser-session S07 implementation and its remaining resource work are tracked in
[durable browser sessions](durable-browser-sessions.md).
